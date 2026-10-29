// Disposable, synthetic-only UI instance. No caller-supplied endpoints or credentials.
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, unlinkSync, openSync, closeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { findAppJar, javaBin } from './workbench-lifecycle.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const stateDir = join(root, '.ui-test');
const handle = join(stateDir, 'instance.json');
const log = join(stateDir, 'app.log');
const windows = process.platform === 'win32';
const command = process.argv[2];
if (process.argv.length !== 3 || !['start', 'serve', 'stop', 'reset'].includes(command)) {
  throw new Error('Usage: node scripts/ui-instance.mjs start|serve|stop|reset');
}

function cleanEnvironment() {
  const forbidden = Object.keys(process.env).filter(key => /^(SPRING_|WORKBENCH_|JAVA_TOOL_OPTIONS$|JDK_JAVA_OPTIONS$|_JAVA_OPTIONS$)/i.test(key));
  if (forbidden.length) throw new Error('Remove configuration overrides before UI testing: ' + forbidden.join(', '));
  // Child Java sees only platform/tool paths: no credentials, provider settings or Spring overrides.
  return Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    /^(PATH|JAVA_HOME|SYSTEMROOT|WINDIR|COMSPEC|TEMP|TMP|HOME|USERPROFILE|SYSTEMDRIVE)$/i.test(key)));
}
async function stop() {
  if (!existsSync(handle)) return;
  const state = JSON.parse(readFileSync(handle, 'utf8'));
  if (!/^http:\/\/127[.]0[.]0[.]1:[0-9]+$/.test(state.control)) throw new Error('Invalid instance control URL');
  const response = await fetch(state.control + '/stop', { method: 'POST', headers: { 'X-Instance': state.token } });
  if (!response.ok) throw new Error('Instance refused teardown');
  for (let i = 0; i < 100 && existsSync(handle); i++) await delay(100);
  if (existsSync(handle)) throw new Error('Teardown did not finish; inspect .ui-test/app.log');
}
function removeData(data) {
  const target = resolve(data);
  if (dirname(target) !== resolve(tmpdir()) || !target.startsWith(resolve(tmpdir()) + sep + 'ui-workbench-')) {
    throw new Error('Refusing removal outside disposable temporary directory');
  }
  // Native PowerShell end-to-end on Windows, after validating the absolute target.
  const result = windows
    ? spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      "Remove-Item -LiteralPath '" + target.replaceAll("'", "''") + "' -Recurse -Force -ErrorAction Stop"], { windowsHide: true })
    : spawnSync('rm', ['-rf', '--', target]);
  if (result.status !== 0 || existsSync(target)) throw new Error('Disposable data cleanup failed');
}
async function serve() {
  const env = cleanEnvironment();
  mkdirSync(stateDir, { recursive: true });
  if (existsSync(handle)) throw new Error('This worktree already owns an instance; stop it first');
  const data = mkdtempSync(join(tmpdir(), 'ui-workbench-'));
  const token = randomUUID();
  let app, control, cleanupPromise;
  let state;
  const cleanup = () => cleanupPromise ??= (async () => {
    if (app?.pid && app.exitCode === null && app.signalCode === null) {
      const exited = once(app, 'exit');
      app.kill();
      await exited;
    }
    removeData(data);
    if (existsSync(handle) && JSON.parse(readFileSync(handle, 'utf8')).token === token) unlinkSync(handle);
    control?.close();
  })();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => cleanup().then(() => process.exit(0)));
  try {
    control = createServer((req, res) => {
      if (req.method !== 'POST' || req.url !== '/stop' || req.headers['x-instance'] !== token) {
        res.writeHead(403).end(); return;
      }
      res.end('Stopping');
      cleanup().catch(error => { console.error(error); process.exitCode = 1; });
    });
    control.listen(0, '127.0.0.1');
    await once(control, 'listening');
    state = { token, control: 'http://127.0.0.1:' + control.address().port,
      baseURL: null, ready: false, pid: null, supervisorPid: process.pid, data, log };
    writeFileSync(handle, JSON.stringify(state), { mode: 0o600, flag: 'wx' });
    const jar = findAppJar(join(root, 'workbench-app', 'target'), 'run ./mvnw verify first');
    const java = javaBin(env);
    const fd = openSync(log, 'w');
    try {
      app = spawn(java, ['-Xmx512m', '-Djava.io.tmpdir=' + data, '-jar', jar,
        '--spring.config.location=classpath:/application.properties', '--server.address=127.0.0.1', '--server.port=0',
        '--workbench.custom-endpoints.enabled=false', '--workbench.audit.journal-dir=' + join(data, 'audit'),
        '--workbench.audit.operator-label=ui-pass'], { cwd: data, env, stdio: ['ignore', fd, fd], windowsHide: true });
    } finally { closeSync(fd); }
    let spawnError;
    app.on('error', error => { spawnError = error; });
    let ready = false;
    for (let i = 0; i < 120; i++) {
      if (spawnError) throw spawnError;
      if (app.exitCode !== null || app.signalCode !== null) throw new Error('Instance exited; see ' + log);
      // Readiness must come from OUR child, never a pre-existing server.
      if (readFileSync(log, 'utf8').includes('Started WorkbenchApplication')) { ready = true; break; }
      await delay(1000);
    }
    if (!ready) throw new Error('Instance startup timeout');
    const port = readFileSync(log, 'utf8').match(/started on port (\d+)/)?.[1];
    if (!port) throw new Error('Owned child did not publish its port');
    const baseURL = 'http://127.0.0.1:' + port;
    const features = await fetch(baseURL + '/api/features').then(r => r.json());
    const payers = await fetch(baseURL + '/api/payers').then(r => r.json());
    if (features.customEndpoints || payers.length !== 3 || payers.some(p => !p.payerId.endsWith('-synthetic'))) {
      throw new Error('Synthetic isolation verification failed');
    }
    state.baseURL = baseURL;
    state.pid = app.pid;
    state.ready = true;
    writeFileSync(handle, JSON.stringify(state), { mode: 0o600 });
    console.log('UI_TEST_URL=' + baseURL);
    await once(app, 'exit');
  } finally { await cleanup(); }
}
async function start() {
  cleanEnvironment();
  mkdirSync(stateDir, { recursive: true });
  if (existsSync(handle)) throw new Error('Stop the existing owned instance first');
  const fd = openSync(join(stateDir, 'supervisor.log'), 'w');
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), 'serve'], {
    cwd: root, detached: true, stdio: ['ignore', fd, fd], windowsHide: true,
  });
  closeSync(fd);
  child.unref();
  let error;
  child.on('error', e => { error = e; });
  for (let i = 0; i < 130; i++) {
    if (error) throw error;
    if (child.exitCode !== null) throw new Error('Startup failed; see .ui-test/supervisor.log');
    if (existsSync(handle)) {
      const state = JSON.parse(readFileSync(handle, 'utf8'));
      if (state.ready) { console.log('UI_TEST_URL=' + state.baseURL); return; }
    }
    await delay(1000);
  }
  await stop();
  throw new Error('Supervisor startup timeout; see .ui-test/supervisor.log');
}
if (command === 'stop') await stop();
else if (command === 'reset') { await stop(); await start(); }
else if (command === 'start') await start();
else await serve();
