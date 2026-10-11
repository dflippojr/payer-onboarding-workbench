// node --experimental-vm-modules --test scripts/workbench-lifecycle.test.mjs
import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
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
  Object.assign(child, { pid: 12345, exitCode: null, signalCode: null, kills: 0 });
  child.kill = () => { child.kills++; return true; };
  const parent = new EventEmitter();
  Object.assign(parent, { platform, env, exits: [], exit(code) { this.exits.push(code); } });
  const calls = { builds: [], spawns: [], opens: [], closes: [], delays: [], logs: [] };
  const context = createContext({ process: parent, console: { log: text => calls.logs.push(text) } });
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
    'node:path': path, 'node:url': url, 'node:events': { once },
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
  return { child, parent, calls, create: module.namespace.createWorkbench, root: module.namespace.root };
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

test('a child error during stop rejects all waiters instead of hanging', async () => {
  const f = await fixture();
  const app = f.create('DEMO_SKIP_BUILD');
  await app.start('app.jar', 'app.log');
  const error = new Error('cannot signal child');
  f.child.kill = () => { f.child.kills++; f.child.emit('error', error); return false; };
  const first = app.stop();
  assert.equal(first, app.stop());
  await assert.rejects(first, value => value === error);
  await assert.rejects(app.stop(), value => value === error);
  assert.equal(f.child.kills, 1);
  assert.equal(f.child.listenerCount('exit'), 0);
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
