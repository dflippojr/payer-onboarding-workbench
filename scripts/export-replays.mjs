#!/usr/bin/env node
// Static replay export; Node 22+, JDK 21, git, synthetic payers only.
// node scripts/export-replays.mjs; EXPORT_SKIP_BUILD=1 reuses the existing jar.
import { spawn, spawnSync } from 'node:child_process';
import { closeSync, copyFileSync, mkdirSync, openSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { once } from 'node:events';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'site-dist');
const work = join(root, 'target', 'export-replays');
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
  if (process.env.EXPORT_SKIP_BUILD !== '1') {
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
  if (!jar) throw new Error('No workbench-app jar; run without EXPORT_SKIP_BUILD');
  for (const dir of [out, work]) rmSync(dir, { recursive: true, force: true });
  mkdirSync(join(out, 'runs'), { recursive: true });
  mkdirSync(work, { recursive: true });
  const log = join(work, 'app.log');
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
  async function request(path, options) {
    const response = await fetch(`${base}${path}`, { ...options, signal: AbortSignal.timeout(120_000) });
    if (!response.ok) throw new Error(`${path}: HTTP ${response.status}: ${await response.text()}`);
    return response;
  }
  const payerHosts = {
    'northwind-synthetic': 'https://crd.northwind-health.example',
    'fabrikam-synthetic': 'https://crd.fabrikam-benefits.example',
    'tailspin-synthetic': 'https://crd.tailspin-health.example',
  };
  const rewrites = new Map();
  for (const payer of await (await request('/api/payers')).json()) {
    const host = payerHosts[payer.payerId] ?? `https://crd.${payer.payerId}.example`;
    for (const connection of payer.connections) {
      for (const [url, replacement] of [[connection.baseUrl, host], [connection.jwksUrl, 'https://workbench.example']]) {
        if (url) {
          const origin = new URL(url).origin;
          // The non-digit guard prevents port 8181 from matching inside port 81810.
          rewrites.set(origin, [new RegExp(`${origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?!\\d)`, 'g'), replacement]);
        }
      }
    }
  }
  if (!rewrites.size) throw new Error('GET /api/payers listed no payer addresses to rewrite');
  let failures = 0;
  let version;
  const runs = [];
  async function record(id, title, teaser, description, payerId, fault, expectations) {
    console.log(`\n==> ${title}`);
    const run = await (await request('/api/runs', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payerId, sampleId: 'order-sign-hospital-bed', faults: fault ? [fault] : [] }),
    })).json();
    if (typeof run.runId !== 'string' || !run.runId) throw new Error('Run response has no runId');
    let text = await (await request(`/api/runs/${encodeURIComponent(run.runId)}/report?format=json`)).text();
    for (const [pattern, replacement] of rewrites.values()) text = text.replace(pattern, () => replacement);
    writeFileSync(join(out, 'runs', `${id}.json`), text);
    const report = JSON.parse(text);
    version ??= report.workbenchVersion;
    const found = report.findings.map(finding => `${finding.severity} ${finding.checkId}`);
    const hasFail = found.some(finding => finding.startsWith('FAIL '));
    console.log(`    Verdict: ${report.verdict.status}`);
    console.log(`    FAIL/WARN: ${found.filter(finding => /^(FAIL|WARN) /.test(finding)).join(', ')}`);
    for (const expected of expectations) {
      const missing = expected === 'no FAIL' ? hasFail : expected === 'a FAIL' ? !hasFail : !found.includes(expected);
      if (missing) {
        console.error(`    MISSING: expected ${expected}`);
        failures++;
      }
    }
    runs.push({ id, title, teaser, description, payerId, payerName: report.payer.displayName,
      fault, verdict: report.verdict.status, file: `runs/${id}.json` });
    console.log(`    site-dist/runs/${id}.json`);
  }
  await record('northwind-healthy', 'Northwind, healthy', 'Healthy connection',
    'OAuth2 client credentials payer; every step passes.', 'northwind-synthetic', null, ['no FAIL', 'PASS auth.token']);
  await record('fabrikam-healthy', 'Fabrikam, healthy', 'Healthy connection',
    'CDS Hooks JWT payer; every step passes.', 'fabrikam-synthetic', null, ['no FAIL', 'PASS response.schema']);
  await record('fabrikam-wrong-audience-reject', 'Fabrikam rejects the token audience', 'Payer expects a different JWT audience',
    'The payer checks the JWT aud against a different URL and rejects the hook call.',
    'fabrikam-synthetic', 'wrong-audience-reject', ['a FAIL']);
  await record('northwind-expired-token-401', 'Northwind says the token expired', 'Token rejected as expired',
    'Hook calls get 401 invalid_token with an expired-token message.', 'northwind-synthetic', 'expired-token-401', ['a FAIL']);
  await record('fabrikam-malformed-card', 'Fabrikam returns malformed cards', 'Cards come back malformed',
    'Cards come back without summary and indicator.', 'fabrikam-synthetic', 'malformed-card', ['FAIL response.schema']);
  console.log('\n    (the next run holds the hook call for about 11 s)');
  await record('northwind-slow-response', 'Northwind is slow', 'Payer is slow',
    'Discovery and auth answer quickly, but the hook call is held past the latency budget.',
    'northwind-synthetic', 'slow-response', ['FAIL perf.latency']);
  await stopApp();
  for (const name of ['replay.js', 'replay.css', 'index.html']) copyFileSync(join(root, 'replay', name), join(out, name));
  const head = spawnSync('git', ['rev-parse', '--short=12', 'HEAD'], { cwd: root, encoding: 'utf8' });
  let commit = head.status === 0 ? head.stdout.trim() : 'unknown';
  const status = spawnSync('git', ['status', '--porcelain', '--untracked-files=no'], { cwd: root, encoding: 'utf8' });
  if (commit !== 'unknown' && status.status === 0 && status.stdout.trim()) commit += '-dirty';
  writeFileSync(join(out, 'manifest.json'), `${JSON.stringify({
    name: 'payer-onboarding-workbench replay bundle', workbenchVersion: version, gitCommit: commit,
    generatedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    disclaimer: 'Recorded run against a synthetic mock payer; addresses rewritten to example hosts. Passing here does not prove real-payer interoperability.',
    runs,
  }, null, 2)}\n`);
  const files = readdirSync(out, { recursive: true, withFileTypes: true }).filter(entry => entry.isFile());
  for (const file of files) {
    const path = join(file.parentPath, file.name);
    const text = readFileSync(path, 'utf8');
    if (/PRIVATE KEY|client_secret=[^\[]/.test(text)) {
      console.error(`The bundle contains unredacted key or secret material: ${path}`);
      failures++;
    }
    if (/localhost|127\.0\.0\.1/.test(text)) {
      console.error(`The bundle still contains local addresses: ${path}`);
      failures++;
    }
  }
  if (failures) throw new Error(`Export FAILED: ${failures} expectation(s) not met. The partial bundle is in site-dist/.`);
  console.log(`\nExport done: ${runs.length} runs in site-dist/. Check it with: node --test replay/test/bundle.test.mjs`);
}

try {
  await main();
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  await stopApp();
}
