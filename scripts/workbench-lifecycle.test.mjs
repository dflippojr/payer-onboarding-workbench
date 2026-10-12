// node --experimental-vm-modules --test --test-timeout=10000 scripts/workbench-lifecycle.test.mjs
// The timeout turns a regression to an unbounded cleanup wait into a failed test instead of a hung job.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import * as url from 'node:url';
import { createContext, SourceTextModule, SyntheticModule } from 'node:vm';

const source = readFileSync(new URL('./workbench-lifecycle.mjs', import.meta.url), 'utf8');
async function fixture({ platform = 'linux', env = {}, jars = ['workbench-app-2.jar',
  'workbench-app-1.jar', 'workbench-app-0.jar.original'], log = 'started on port 43210',
  buildResult = { status: 0 }, spawnError, synchronousError, afterDelay } = {}) {
  const child = new EventEmitter();
  Object.assign(child, { pid: 12345, exitCode: null, signalCode: null, kills: 0, signals: [], unrefs: 0 });
  child.kill = signal => { child.kills++; child.signals.push(signal); return true; };
  child.unref = () => { child.unrefs++; };
  const parent = new EventEmitter();
  Object.assign(parent, { platform, env, exits: [], exit(code) { this.exits.push(code); } });
  const calls = { builds: [], spawns: [], opens: [], closes: [], delays: [], logs: [], errors: [] };
  let now = 0, nextTimer = 0;
  const timers = new Map();
  function advance(ms) {
    const end = now + ms;
    while (true) {
      const due = [...timers].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      const [id, timer] = due;
      timers.delete(id);
      now = timer.at;
      timer.callback();
    }
    now = end;
  }
  const context = createContext({ process: parent, console: {
    log: text => calls.logs.push(text), error: text => calls.errors.push(text),
  }, setTimeout(callback, ms) { const id = ++nextTimer; timers.set(id, { callback, at: now + ms }); return id; },
  clearTimeout(id) { timers.delete(id); } });
  const modules = {
    'node:child_process': {
      spawnSync(...args) { calls.builds.push(args); return buildResult; },
      spawn(...args) {
        calls.spawns.push(args);
        if (synchronousError) throw synchronousError;
        if (spawnError) { child.pid = undefined; queueMicrotask(() => child.emit('error', spawnError)); }
        return child;
      },
    },
    'node:fs': {
      readdirSync: () => [...jars], readFileSync: () => log,
      openSync(...args) { calls.opens.push(args); return 42; },
      closeSync(fd) { calls.closes.push(fd); },
    },
    'node:path': path, 'node:url': url,
    'node:timers/promises': { async setTimeout(ms) {
      calls.delays.push(ms);
      afterDelay?.(child, calls.delays.length);
    } },
  };
  const module = new SourceTextModule(source, { context,
    initializeImportMeta(meta) { meta.url = new URL('./workbench-lifecycle.mjs', import.meta.url).href; } });
  await module.link(specifier => {
    const values = modules[specifier];
    return new SyntheticModule(Object.keys(values), function () {
      for (const [key, value] of Object.entries(values)) this.setExport(key, value);
    }, { context });
  });
  await module.evaluate();
  return { child, parent, calls, timers, advance, create: module.namespace.createWorkbench, root: module.namespace.root };
}

test('import is inert; creation installs signals but does not build or spawn', async () => {
  const f = await fixture();
  assert.deepEqual(f.parent.eventNames(), []);
  const app = f.create('DEMO_SKIP_BUILD');
  assert.deepEqual(f.parent.eventNames(), ['SIGINT', 'SIGTERM']);
  assert.deepEqual(f.calls.builds, []);
  assert.deepEqual(f.calls.spawns, []);
  await app.stop();
  assert.equal(f.child.kills, 0);
});

for (const platform of ['linux', 'win32']) {
  test(`build and Java resolution on ${platform}; sorted jar and descriptor ownership`, async () => {
    const f = await fixture({ platform, env: { JAVA_HOME: path.resolve('jdk') } });
    const app = f.create('DEMO_SKIP_BUILD');
    const jar = app.build();
    assert.equal(jar, path.join(f.root, 'workbench-app', 'target', 'workbench-app-1.jar'));
    const [command, args, options] = f.calls.builds[0];
    assert.equal(command, platform === 'win32' ? 'cmd.exe' : './mvnw');
    assert.deepEqual(Array.from(args), [...(platform === 'win32' ? ['/d', '/c', '.\\mvnw.cmd'] : []),
      '-B', '-q', '-pl', 'workbench-app', '-am', 'package', '-DskipTests']);
    assert.equal(options.cwd, f.root);
    assert.equal(options.stdio, 'inherit');
    assert.equal(await app.start(jar, 'app.log'), 'http://127.0.0.1:43210');
    const [java, javaArgs, javaOptions] = f.calls.spawns[0];
    assert.equal(java, path.join(path.resolve('jdk'), 'bin', platform === 'win32' ? 'java.exe' : 'java'));
    assert.deepEqual(Array.from(javaArgs), ['-jar', jar, '--server.port=0']);
    assert.deepEqual(Array.from(javaOptions.stdio), ['ignore', 42, 42]);
    assert.equal(javaOptions.cwd, f.root);
    assert.equal(javaOptions.windowsHide, true);
    assert.deepEqual(f.calls.opens.map(args => Array.from(args)), [['app.log', 'w']]);
    assert.deepEqual(f.calls.closes, [42]);
  });
}

for (const skip of ['DEMO_SKIP_BUILD', 'EXPORT_SKIP_BUILD']) {
  test(`${skip} skips only for 1 and retains the missing-jar message`, async () => {
    const f = await fixture({ env: { [skip]: '1' }, jars: [] });
    assert.throws(() => f.create(skip).build(), { message: `No workbench-app jar; run without ${skip}` });
    assert.equal(f.calls.builds.length, 0);
    const other = await fixture({ env: { [skip]: 'true' } });
    other.create(skip).build();
    assert.equal(other.calls.builds.length, 1);
  });
}

test('Maven spawn and nonzero status failures retain their errors', async () => {
  const error = new Error('wrapper missing');
  const f = await fixture({ buildResult: { error } });
  assert.throws(() => f.create('DEMO_SKIP_BUILD').build(), value => value === error);
  const failed = await fixture({ buildResult: { status: 7 } });
  assert.throws(() => failed.create('DEMO_SKIP_BUILD').build(), { message: 'Build failed with exit code 7' });
});

test('spawn failure closes the descriptor and cleanup never signals a missing child', async () => {
  const error = new Error('java missing');
  const f = await fixture({ spawnError: error, log: '' });
  const app = f.create('DEMO_SKIP_BUILD');
  await assert.rejects(app.start('app.jar', 'app.log'), value => value === error);
  assert.deepEqual(f.calls.closes, [42]);
  await app.stop();
  assert.equal(f.child.kills, 0);
  assert.equal(f.calls.spawns[0][0], 'java');
  const sync = await fixture({ synchronousError: error });
  await assert.rejects(sync.create('DEMO_SKIP_BUILD').start('app.jar', 'app.log'), value => value === error);
  assert.deepEqual(sync.calls.closes, [42]);
});

for (const exit of [{ exitCode: 9 }, { signalCode: 'SIGTERM' }]) {
  test(`early exit (${JSON.stringify(exit)}) retains log hint and cleanup does not kill`, async () => {
    const f = await fixture({ log: '', afterDelay(child) { Object.assign(child, exit); child.emit('exit'); } });
    const app = f.create('EXPORT_SKIP_BUILD');
    await assert.rejects(app.start('app.jar', 'export/app.log'),
      { message: 'The workbench exited during startup; see export/app.log' });
    await app.stop();
    assert.equal(f.child.kills, 0);
  });
}

test('startup timeout polls 120 times at 1 s and cleanup waits for the exact child', async () => {
  const f = await fixture({ log: '' });
  const app = f.create('EXPORT_SKIP_BUILD');
  await assert.rejects(app.start('app.jar', 'export/app.log'),
    { message: 'The workbench did not start within 120 s; see export/app.log' });
  assert.deepEqual(f.calls.delays, Array(120).fill(1000));
  const stopped = app.stop();
  f.child.exitCode = 0;
  f.child.emit('exit', 0);
  await stopped;
  assert.equal(f.child.kills, 1);
});

test('concurrent and repeated stops share one pending exit and signal only the owned child', async () => {
  const f = await fixture();
  const unrelated = new EventEmitter();
  let unrelatedKills = 0;
  unrelated.kill = () => { unrelatedKills++; };
  const app = f.create('DEMO_SKIP_BUILD');
  await app.start('app.jar', 'app.log');
  let settled = false;
  const first = app.stop();
  first.then(() => { settled = true; });
  const second = app.stop();
  assert.equal(first, second);
  await Promise.resolve();
  assert.equal(settled, false);
  assert.equal(f.child.kills, 1);
  assert.equal(f.child.listenerCount('exit'), 1);
  unrelated.emit('exit', 0);
  await Promise.resolve();
  assert.equal(settled, false);
  f.child.signalCode = 'SIGTERM';
  f.child.emit('exit', null, 'SIGTERM');
  await Promise.all([first, second, app.stop()]);
  assert.equal(f.child.kills, 1);
  assert.equal(unrelatedKills, 0);
});

for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
  test(`${signal} waits for cleanup then exits ${code}, including a concurrent finally stop`, async () => {
    const f = await fixture();
    const app = f.create('DEMO_SKIP_BUILD');
    await app.start('app.jar', 'app.log');
    f.parent.emit(signal);
    const stopped = app.stop();
    await Promise.resolve();
    assert.deepEqual(f.parent.exits, []);
    assert.equal(f.child.kills, 1);
    f.child.exitCode = 0;
    f.child.emit('exit', 0);
    await stopped;
    await Promise.resolve();
    assert.deepEqual(f.parent.exits, [code]);
    assert.equal(f.child.kills, 1);
  });
}

function assertCleanStop(f) {
  assert.equal(f.child.listenerCount('exit'), 0);
  // The startup error observer remains; cleanup adds no lasting error listener.
  assert.equal(f.child.listenerCount('error'), 1);
  assert.equal(f.timers.size, 0);
}

test('a stubborn child gets only owned SIGKILL after the full grace period', async () => {
  const f = await fixture();
  const unrelated = new EventEmitter();
  let unrelatedKills = 0;
  unrelated.kill = () => { unrelatedKills++; };
  const app = f.create('DEMO_SKIP_BUILD');
  await app.start('app.jar', 'app.log');
  const stopped = app.stop();
  f.advance(4999);
  assert.deepEqual(f.child.signals, ['SIGTERM']);
  unrelated.emit('exit');
  f.advance(1);
  assert.deepEqual(f.child.signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(stopped, app.stop());
  assert.equal(f.timers.size, 1);
  f.advance(4999);
  f.child.signalCode = 'SIGKILL';
  f.child.emit('exit', null, 'SIGKILL');
  await stopped;
  f.advance(10000);
  assertCleanStop(f);
  assert.equal(f.child.unrefs, 0);
  assert.equal(unrelatedKills, 0);
});

test('final exit timeout rejects every waiter and releases the live child handle', async () => {
  const f = await fixture();
  const app = f.create('EXPORT_SKIP_BUILD');
  await app.start('app.jar', 'app.log');
  const first = app.stop();
  const rejected = assert.rejects(first, /owned child PID 12345 did not exit within 5000 ms after SIGKILL/);
  assert.equal(first, app.stop());
  f.advance(10000);
  await rejected;
  assert.equal(first, app.stop());
  await assert.rejects(app.stop(), /cleanup failed/);
  assert.deepEqual(f.child.signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(f.child.unrefs, 1);
  assertCleanStop(f);
  f.child.emit('exit', 0);
  f.advance(10000);
  assert.equal(f.child.unrefs, 1);
});

for (const outcome of ['false', 'throw', 'error']) {
  test('SIGTERM ' + outcome + ' immediately escalates and can still observe exit', async () => {
    const f = await fixture();
    const app = f.create('DEMO_SKIP_BUILD');
    await app.start('app.jar', 'app.log');
    const kill = f.child.kill;
    f.child.kill = signal => {
      kill(signal);
      if (signal === 'SIGKILL') { f.child.emit('exit', null, signal); return true; }
      if (outcome === 'throw') throw new Error('denied');
      if (outcome === 'error') f.child.emit('error', new Error('denied'));
      return false;
    };
    const first = app.stop();
    assert.equal(first, app.stop());
    await first;
    assert.deepEqual(f.child.signals, ['SIGTERM', 'SIGKILL']);
    assertCleanStop(f);
  });

  test('SIGKILL ' + outcome + ' is bounded and preserves useful failure detail', async () => {
    const f = await fixture();
    const app = f.create('EXPORT_SKIP_BUILD');
    await app.start('app.jar', 'app.log');
    const kill = f.child.kill;
    f.child.kill = signal => {
      kill(signal);
      if (signal === 'SIGTERM') return true;
      if (outcome === 'throw') throw new Error('denied');
      if (outcome === 'error') f.child.emit('error', new Error('denied'));
      return false;
    };
    const stopped = app.stop();
    const rejected = assert.rejects(stopped, outcome === 'false' ? /SIGKILL kill[(][)] returned false/ : /SIGKILL: denied/);
    f.advance(10000);
    await rejected;
    assert.equal(stopped, app.stop());
    assert.equal(f.child.unrefs, 1);
    assertCleanStop(f);
  });
}

test('false for both kills without events retains both outcomes', async () => {
  const f = await fixture();
  const app = f.create('DEMO_SKIP_BUILD');
  await app.start('app.jar', 'app.log');
  f.child.kill = signal => { f.child.signals.push(signal); return false; };
  const stopped = app.stop();
  const rejected = assert.rejects(stopped, /SIGTERM kill[(][)] returned false; SIGKILL kill[(][)] returned false/);
  assert.deepEqual(f.child.signals, ['SIGTERM', 'SIGKILL']);
  f.advance(5000);
  await rejected;
  assertCleanStop(f);
});

test('an asynchronous graceful kill error escalates without duplicate force attempts', async () => {
  const f = await fixture();
  const app = f.create('DEMO_SKIP_BUILD');
  await app.start('app.jar', 'app.log');
  const stopped = app.stop();
  f.child.emit('error', new Error('SIGTERM failed'));
  f.child.emit('error', new Error('SIGKILL failed'));
  assert.deepEqual(f.child.signals, ['SIGTERM', 'SIGKILL']);
  f.child.exitCode = 0;
  f.child.emit('exit', 0);
  await stopped;
  assertCleanStop(f);
});

for (const phase of ['SIGTERM', 'SIGKILL']) {
  test('synchronous exit during ' + phase + ' clears waits and shares a reentrant stop', async () => {
    const f = await fixture();
    const app = f.create('DEMO_SKIP_BUILD');
    await app.start('app.jar', 'app.log');
    let reentrant;
    const kill = f.child.kill;
    f.child.kill = signal => {
      kill(signal);
      reentrant = app.stop();
      if (signal === phase) f.child.emit('exit', 0);
      return false;
    };
    const first = app.stop();
    assert.equal(first, reentrant);
    await first;
    assert.deepEqual(f.child.signals, phase === 'SIGTERM' ? ['SIGTERM'] : ['SIGTERM', 'SIGKILL']);
    assertCleanStop(f);
  });
}

for (const elapsed of [5000, 10000]) {
  test('exit state racing a timeout at ' + elapsed + ' ms wins without an exit event', async () => {
    const f = await fixture();
    const app = f.create('DEMO_SKIP_BUILD');
    await app.start('app.jar', 'app.log');
    const stopped = app.stop();
    f.advance(elapsed - 1);
    f.child.exitCode = 0;
    f.advance(1);
    await stopped;
    assert.equal(f.child.kills, elapsed === 5000 ? 1 : 2);
    assertCleanStop(f);
  });
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  test(signal + ' reports rejected cleanup and exits 1 without an unhandled rejection', async () => {
    const f = await fixture();
    const app = f.create('DEMO_SKIP_BUILD');
    await app.start('app.jar', 'app.log');
    f.parent.emit(signal);
    const stopped = app.stop();
    const rejected = assert.rejects(stopped, /cleanup failed/);
    f.advance(10000);
    await rejected;
    assert.deepEqual(f.parent.exits, [1]);
    assert.match(f.calls.errors[0], /owned child PID 12345/);
    assertCleanStop(f);
  });
}

for (const script of ['demo.mjs', 'export-replays.mjs']) {
  test(script + ' explicitly reports cleanup rejection in its finally path', async () => {
    const errors = [];
    const parent = { exitCode: 0 };
    let stops = 0;
    const context = createContext({ process: parent, console: { error: message => errors.push(message) } });
    const lifecycle = { root: '.', createWorkbench: () => ({
      build() { throw new Error('build failed'); },
      async stop() { stops++; throw new Error('cleanup failed'); },
    }) };
    const modules = { 'node:path': path, 'node:child_process': { spawnSync() {} },
      'node:fs': Object.fromEntries(['mkdirSync', 'readdirSync', 'readFileSync', 'rmSync', 'writeFileSync', 'copyFileSync']
        .map(name => [name, () => {}])), './workbench-lifecycle.mjs': lifecycle };
    const module = new SourceTextModule(readFileSync(new URL(script, import.meta.url), 'utf8'), { context });
    await module.link(specifier => {
      const values = modules[specifier];
      return new SyntheticModule(Object.keys(values), function () {
        for (const [key, value] of Object.entries(values)) this.setExport(key, value);
      }, { context });
    });
    await module.evaluate();
    assert.equal(stops, 1);
    assert.equal(parent.exitCode, 1);
    assert.deepEqual(errors, ['build failed', 'cleanup failed']);
  });
}

for (const second of ['SIGINT', 'SIGTERM']) {
  test('a second ' + second + ' in the grace window forces SIGKILL but exits only after the child', async () => {
    const f = await fixture();
    const app = f.create('DEMO_SKIP_BUILD');
    await app.start('app.jar', 'app.log');
    f.parent.emit('SIGINT');
    assert.equal(f.calls.logs.at(-1), 'Stopping workbench PID 12345 (Ctrl+C again to force)');
    f.advance(1000);
    assert.deepEqual(f.child.signals, ['SIGTERM']);
    f.parent.emit(second);
    assert.deepEqual(f.child.signals, ['SIGTERM', 'SIGKILL']);
    f.parent.emit(second);
    assert.deepEqual(f.child.signals, ['SIGTERM', 'SIGKILL']);
    await Promise.resolve();
    assert.deepEqual(f.parent.exits, []);
    assert.equal(f.calls.logs.filter(line => line.startsWith('Stopping')).length, 1);
    f.child.signalCode = 'SIGKILL';
    f.child.emit('exit', null, 'SIGKILL');
    await app.stop();
    await Promise.resolve();
    assert.deepEqual(f.parent.exits, [130]);
    assertCleanStop(f);
  });
}

test('a forced child that never exits still reports the bounded cleanup failure', async () => {
  const f = await fixture();
  const app = f.create('DEMO_SKIP_BUILD');
  await app.start('app.jar', 'app.log');
  f.parent.emit('SIGTERM');
  f.parent.emit('SIGINT');
  const rejected = assert.rejects(app.stop(), /did not exit within 5000 ms after SIGKILL/);
  f.advance(4999);
  assert.deepEqual(f.parent.exits, []);
  f.advance(1);
  await rejected;
  await Promise.resolve();
  assert.deepEqual(f.parent.exits, [1]);
  assert.deepEqual(f.child.signals, ['SIGTERM', 'SIGKILL']);
  assertCleanStop(f);
});

test('signals without an owned child print no hint and repeat harmlessly', async () => {
  const f = await fixture();
  f.create('DEMO_SKIP_BUILD');
  f.parent.emit('SIGINT');
  f.parent.emit('SIGINT');
  await Promise.resolve();
  await Promise.resolve();
  assert.deepEqual(f.parent.exits, [130]);
  assert.deepEqual(f.calls.logs, []);
  assert.equal(f.child.kills, 0);
});

for (const env of [{}, { JAVA_HOME: path.resolve('jdk') }]) {
  test('Windows warns about a PATH java shim only without JAVA_HOME ' + JSON.stringify(Object.keys(env)), async () => {
    const f = await fixture({ platform: 'win32', env });
    await f.create('DEMO_SKIP_BUILD').start('app.jar', 'app.log');
    const warned = f.calls.logs.some(line => /launcher shim/.test(line));
    assert.equal(warned, !env.JAVA_HOME);
    const posix = await fixture();
    await posix.create('DEMO_SKIP_BUILD').start('app.jar', 'app.log');
    assert.equal(posix.calls.logs.some(line => /launcher shim/.test(line)), false);
  });
}
