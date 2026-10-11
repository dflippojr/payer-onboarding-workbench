// App lifecycle shared by the synthetic demo and replay export; importing does no work.
import { spawn, spawnSync } from 'node:child_process';
import { closeSync, openSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export function createWorkbench(skipBuild) {
  const windows = process.platform === 'win32';
  let app, stopping;
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
    const target = join(root, 'workbench-app', 'target');
    const jar = readdirSync(target).sort().find(name => /^workbench-app-.*\.jar$/.test(name));
    if (!jar) throw new Error(`No workbench-app jar; run without ${skipBuild}`);
    return join(target, jar);
  }
  function stop() {
    if (!stopping && app?.pid && app.exitCode === null && app.signalCode === null) {
      stopping = new Promise(resolve => app.once('exit', resolve));
      app.kill();
    }
    return stopping ?? Promise.resolve();
  }
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => {
      stop().finally(() => process.exit(signal === 'SIGINT' ? 130 : 143));
    });
  }
  async function start(jar, log) {
    const fd = openSync(log, 'w');
    console.log('==> Starting the workbench on a free port');
    const java = process.env.JAVA_HOME
      ? join(process.env.JAVA_HOME, 'bin', windows ? 'java.exe' : 'java') : 'java';
    try {
      app = spawn(java, ['-jar', jar, '--server.port=0'], {
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
