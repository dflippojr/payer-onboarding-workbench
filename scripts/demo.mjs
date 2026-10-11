#!/usr/bin/env node
// Repeatable REST demo; Node 22+, JDK 21, synthetic payers only.
// node scripts/demo.mjs; DEMO_SKIP_BUILD=1 reuses the existing jar.
import { createWorkbench, root } from './workbench-lifecycle.mjs';
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = join(root, 'demo-output');
const app = createWorkbench('DEMO_SKIP_BUILD');

async function main() {
  const jar = app.build();
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const base = await app.start(jar, join(out, 'app.log'));
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
  await app.stop();
}
