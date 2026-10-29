import { spawn, spawnSync } from 'node:child_process';
import { closeSync, existsSync, openSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
// Allow 5 s for SIGTERM, then at most 5 s to observe SIGKILL's exit.
const STOP_GRACE_MS = 5000;
const STOP_FORCE_MS = 5000;

// The only app-jar lookup. A second jar is a stale build left by a version bump without clean,
// and picking the first one would start the old code.
export function findAppJar(target, noJarHint) {
  const jars = existsSync(target)
    ? readdirSync(target).filter(name => /^workbench-app-.*\.jar$/.test(name)).sort() : [];
  if (jars.length > 1) {
    throw new Error(`Found ${jars.length} workbench-app jars in ${target} (${jars.join(', ')}); `
      + 'run ./mvnw clean package so only the current build remains');
  }
  if (jars.length === 0) throw new Error(`No workbench-app jar; ${noJarHint}`);
  return join(target, jars[0]);
}

// The one java lookup for the app-launching scripts, so they all start the same JVM.
export function javaBin(env = process.env) {
  const windows = process.platform === 'win32';
  return env.JAVA_HOME ? join(env.JAVA_HOME, 'bin', windows ? 'java.exe' : 'java') : 'java';
}

function prepareStop(child) {
  let resolveStop, rejectStop, timer, forcing = false, settled = false;
  const failures = [];
  const promise = new Promise((resolve, reject) => { resolveStop = resolve; rejectStop = reject; });
  const exited = () => child.exitCode !== null || child.signalCode !== null;
  function finish(error) {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    child.removeListener('exit', onExit);
    child.removeListener('error', onError);
    if (error) {
      // A live ChildProcess handle must not keep the failed script alive.
      // This releases the parent's handle; it does not claim the child exited.
      child.unref();
      rejectStop(error);
    } else resolveStop();
  }
  function onExit() { finish(); }
  function signal(name) {
    try {
      if (!child.kill(name)) failures.push(name + ' kill() returned false');
    } catch (error) {
      failures.push(name + ': ' + error.message);
    }
  }
  function force() {
    if (settled || forcing) return;
    if (exited()) { finish(); return; }
    forcing = true;
    clearTimeout(timer);
    timer = setTimeout(() => {
      if (exited()) { finish(); return; }
      const detail = failures.length ? '; ' + failures.join('; ') : '';
      finish(new Error('Workbench cleanup failed: owned child PID ' + child.pid
        + ' did not exit within ' + STOP_FORCE_MS + ' ms after SIGKILL' + detail));
    }, STOP_FORCE_MS);
    signal('SIGKILL');
    if (exited()) finish();
  }
  function onError(error) {
    failures.push((forcing ? 'SIGKILL' : 'SIGTERM') + ': ' + error.message);
    force();
  }
  function terminate() {
    child.on('exit', onExit);
    child.on('error', onError);
    if (exited()) { finish(); return; }
    timer = setTimeout(force, STOP_GRACE_MS);
    signal('SIGTERM');
    if (exited()) finish();
    else if (failures.length) force();
  }
  return { promise, terminate, force };
}

export function createWorkbench(skipBuild) {
  const windows = process.platform === 'win32';
  let app, stopping, shutdown, interrupted = false;
  function build() {
    if (process.env[skipBuild] !== '1') {
      console.log('==> Building (tests skipped; run ./mvnw verify for those)');
      const args = ['-B', '-q', '-pl', 'workbench-app', '-am', 'package', '-DskipTests'];
      const result = windows
        ? spawnSync('cmd.exe', ['/d', '/c', '.\\mvnw.cmd', ...args], { cwd: root, stdio: 'inherit', windowsHide: true })
        : spawnSync('./mvnw', args, { cwd: root, stdio: 'inherit' });
      if (result.error) throw result.error;
      if (result.status !== 0) throw new Error(`Build failed with exit code ${result.status}`);
    }
    return findAppJar(join(root, 'workbench-app', 'target'), `run without ${skipBuild}`);
  }
  function stop() {
    if (!stopping && app?.pid && app.exitCode === null && app.signalCode === null) {
      shutdown = prepareStop(app);
      // Publish the shared promise before kill() can emit exit/error or reenter stop().
      stopping = shutdown.promise;
      shutdown.terminate();
    }
    return stopping ?? Promise.resolve();
  }
  // Stay subscribed: with once(), a second Ctrl+C would take Node's default exit
  // and orphan a JVM that is still inside its grace period.
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
      if (interrupted) {
        // Escalate now; the first signal's handler still exits only after the child is gone.
        shutdown?.force();
        return;
      }
      interrupted = true;
      const pending = stop();
      if (shutdown) console.log(`Stopping workbench PID ${app.pid} (Ctrl+C again to force)`);
      pending.then(
        () => process.exit(signal === 'SIGINT' ? 130 : 143),
        error => { console.error(error.message); process.exit(1); },
      );
    });
  }
  // args are extra application arguments, e.g. --workbench.custom-endpoints.enabled=true.
  async function start(jar, log, args = []) {
    const fd = openSync(log, 'w');
    console.log('==> Starting the workbench on a free port');
    const java = javaBin();
    if (windows && !process.env.JAVA_HOME) {
      console.log('    JAVA_HOME is unset; if java on the PATH is a launcher shim, cleanup can leave the JVM running');
    }
    try {
      app = spawn(java, ['-jar', jar, '--server.port=0', ...args], {
        cwd: root, stdio: ['ignore', fd, fd], windowsHide: true,
      });
    } finally {
      closeSync(fd);
    }
    let startupError;
    app.on('error', error => { startupError = error; });
    let port;
    for (let attempt = 0; attempt < 120; attempt++) {
      if (startupError) throw startupError;
      if (app.exitCode !== null || app.signalCode !== null) {
        throw new Error(`The workbench exited during startup; see ${log}`);
      }
      port = readFileSync(log, 'utf8').match(/started on port (\d+)/)?.[1];
      if (port) break;
      await delay(1000);
    }
    if (!port) throw new Error(`The workbench did not start within 120 s; see ${log}`);
    const base = `http://127.0.0.1:${port}`;
    console.log(`    ${base}`);
    return base;
  }
  return { build, start, stop };
}
