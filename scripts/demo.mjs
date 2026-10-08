#!/usr/bin/env node
// Repeatable REST demo; Node 22+, JDK 21, synthetic payers only.
// node scripts/demo.mjs; DEMO_SKIP_BUILD=1 reuses the existing jar.
import { spawn, spawnSync } from 'node:child_process';
import { closeSync, mkdirSync, openSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { once } from 'node:events';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'demo-output');
const windows = process.platform === 'win32';
let app;

async function stopApp() {
  if (app?.pid && app.exitCode === null && app.signalCode === null) {
    const exited = once(app, 'exit');
    app.kill();
    await exited;
  }
}
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    stopApp().finally(() => process.exit(signal === 'SIGINT' ? 130 : 143));
  });
}

async function main() {
  if (process.env.DEMO_SKIP_BUILD !== '1') {
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
  if (!jar) throw new Error('No workbench-app jar; run without DEMO_SKIP_BUILD');
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const log = join(out, 'app.log');
  const fd = openSync(log, 'w');
  console.log('==> Starting the workbench on a free port');
  const java = process.env.JAVA_HOME
    ? join(process.env.JAVA_HOME, 'bin', windows ? 'java.exe' : 'java') : 'java';
  try {
    app = spawn(java, ['-jar', join(target, jar), '--server.port=0'], {
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
  let failures = 0;
  let step = 0;
  async function request(path, options) {
    const response = await fetch(`${base}${path}`, { ...options, signal: AbortSignal.timeout(120_000) });
    if (!response.ok) throw new Error(`${path}: HTTP ${response.status}: ${await response.text()}`);
    return response;
  }
  async function tour(name, title, payerId, faults, expectations) {
    const prefix = `${String(++step).padStart(2, '0')}-${name}`;
    console.log(`\n==> ${step}. ${title}`);
    const run = await (await request('/api/runs', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payerId, sampleId: 'order-sign-hospital-bed', ...(faults ? { faults } : {}) }),
    })).json();
    if (typeof run.runId !== 'string' || !run.runId) throw new Error('Run response has no runId');
    for (const format of ['md', 'html', 'json']) {
      const response = await request(`/api/runs/${encodeURIComponent(run.runId)}/report?format=${format}`);
      writeFileSync(join(out, `${prefix}.${format}`), Buffer.from(await response.arrayBuffer()));
    }
    const report = JSON.parse(readFileSync(join(out, `${prefix}.json`), 'utf8'));
    const found = report.findings.map(finding => `${finding.severity} ${finding.checkId}`);
    console.log(`    Verdict: ${report.verdict.status}`);
    console.log(`    FAIL/WARN: ${found.filter(finding => /^(FAIL|WARN) /.test(finding)).join(', ')}`);
    for (const expected of expectations) {
      if (expected === 'no FAIL' ? found.some(finding => finding.startsWith('FAIL ')) : !found.includes(expected)) {
        console.error(`    MISSING: expected ${expected === 'no FAIL' ? 'no FAIL findings' : `finding ${expected}`}`);
        failures++;
      }
    }
    console.log(`    reports: demo-output/${prefix}.{md,html,json}`);
  }
  await tour('healthy-northwind', 'Northwind (OAuth2 client credentials), healthy', 'northwind-synthetic', undefined,
    ['no FAIL', 'PASS discovery.reachable', 'PASS auth.token', 'PASS response.schema']);
  await tour('healthy-fabrikam', 'Fabrikam (CDS Hooks JWT), healthy', 'fabrikam-synthetic', undefined,
    ['no FAIL', 'PASS discovery.reachable', 'PASS ig.version', 'PASS response.schema']);
  await tour('fabrikam-wrong-audience', 'Fabrikam with wrong-audience-reject: the payer rejects the JWT audience',
    'fabrikam-synthetic', ['wrong-audience-reject'], ['FAIL auth.jwt-audience']);
  console.log('\n    (the next run holds the hook call for about 11 s)');
  await tour('northwind-slow-response', 'Northwind with slow-response: the hook call is past the latency budget',
    'northwind-synthetic', ['slow-response'], ['FAIL perf.latency']);
  if (readdirSync(out).filter(name => /\.(md|html|json)$/.test(name))
    .some(name => /PRIVATE KEY|client_secret=[^\[]/.test(readFileSync(join(out, name), 'utf8')))) {
    console.error('A report contains unredacted key or secret material');
    failures++;
  }
  if (failures) throw new Error(`Demo FAILED: ${failures} expectation(s) not met. Reports are in demo-output/.`);
  console.log(`\nDemo passed: ${step} runs, every expected finding present. Reports are in demo-output/.`);
}

try {
  await main();
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  await stopApp();
}
