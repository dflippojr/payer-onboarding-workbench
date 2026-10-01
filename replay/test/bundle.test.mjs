// Checks the exported replay bundle (site-dist/ by default, or $REPLAY_BUNDLE_DIR).
// Run scripts/export-replays.sh first, then: node --test replay/test/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { findJsonLeaks, findTextLeaks } from './leaks.mjs';
import { installFakeDom } from './fake-dom.mjs';

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const dist = resolve(process.env.REPLAY_BUNDLE_DIR || join(root, 'site-dist'));
const DISCLAIMER = 'Recorded run against a synthetic mock payer. Passing here does not prove real-payer interoperability.';

/** The scenarios the bundle must contain, as payerId/fault (null = healthy). */
const REQUIRED = [
  ['northwind-synthetic', null], ['fabrikam-synthetic', null],
  ['fabrikam-synthetic', 'wrong-audience-reject'], ['northwind-synthetic', 'slow-response'],
  ['northwind-synthetic', 'expired-token-401'], ['fabrikam-synthetic', 'malformed-card'],
];

function bundleFiles(dir = dist) {
  return readdirSync(dir).flatMap(name => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? bundleFiles(p) : [p];
  });
}

function requireBundle() {
  assert.ok(existsSync(join(dist, 'manifest.json')),
    `No bundle at ${dist}; run scripts/export-replays.sh (or .ps1) first`);
  return JSON.parse(readFileSync(join(dist, 'manifest.json'), 'utf8'));
}

const b64url = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');

// ---- the leak scanner itself, against synthetic material generated here ----

test('leak scanner flags unredacted credentials', () => {
  const secret = randomBytes(18).toString('base64url');
  const jwt = `${b64url({ alg: 'RS256', typ: 'JWT' })}.${b64url({ iss: 'synthetic', aud: 'x' })}.${secret}`;
  const pem = ['-----BEGIN ', 'PRIVATE KEY-----\n', secret, '\n-----END ', 'PRIVATE KEY-----'].join('');
  const samples = {
    'PEM block': pem,
    'Bearer/Basic credential': `Authorization: Bearer ${secret}`,
    'signed JWT': `client_assertion is ${jwt}`,
    'JSON secret field': JSON.stringify({ body: JSON.stringify({ access_token: secret }) }),
    'form secret': `grant_type=client_credentials&client_secret=${secret}`,
  };
  for (const [check, text] of Object.entries(samples)) {
    assert.ok(findTextLeaks(text).some(l => l.check === check), `${check} not detected in ${text}`);
  }
  assert.equal(findJsonLeaks({ details: { clientSecret: secret } }).length, 1);
  assert.equal(findJsonLeaks({ requestHeaders: { Authorization: [`Bearer ${secret}`] } }).length, 1);
  assert.equal(findJsonLeaks({ responseBody: JSON.stringify({ refresh_token: secret }) }).length, 1);
});

test('leak scanner accepts redacted values and prose', () => {
  const header = b64url({ alg: 'RS256', typ: 'JWT' });
  const claims = b64url({ iss: 'synthetic' });
  const text = [
    'Authorization: Bearer [REDACTED]', 'Basic [REDACTED]', 'the payer wants a bearer token',
    `${header}.${claims}.[REDACTED]`, 'client_secret=[REDACTED]&grant_type=client_credentials',
    JSON.stringify({ body: JSON.stringify({ access_token: '[REDACTED]', token_type: 'Bearer' }) }),
  ].join('\n');
  assert.deepEqual(findTextLeaks(text), []);
  assert.deepEqual(findJsonLeaks({
    requestHeaders: { Authorization: ['Bearer [REDACTED]'] },
    details: { clientSecret: '[REDACTED]', credentialConfigured: true },
  }), []);
});

// ---- the exported bundle ----

test('manifest has version, commit, generation time and every required scenario', () => {
  const manifest = requireBundle();
  assert.match(manifest.workbenchVersion, /\S/);
  assert.match(manifest.gitCommit, /^([0-9a-f]{7,40}(-dirty)?|unknown)$/);
  assert.ok(!Number.isNaN(Date.parse(manifest.generatedAt)), 'generatedAt is not a date');
  assert.equal(manifest.disclaimer, DISCLAIMER);
  assert.ok(Array.isArray(manifest.runs) && manifest.runs.length >= REQUIRED.length);
  for (const [payerId, fault] of REQUIRED) {
    assert.ok(manifest.runs.some(r => r.payerId === payerId && (r.fault ?? null) === fault),
      `missing run for ${payerId} ${fault || 'healthy'}`);
  }
  const ids = manifest.runs.map(r => r.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate run ids');
});

test('every run in the manifest loads as a report', () => {
  const manifest = requireBundle();
  for (const run of manifest.runs) {
    assert.match(run.title, /\S/, `${run.id} has no title`);
    assert.match(run.file, /^runs\/[a-z0-9-]+\.json$/, `${run.id} file path`);
    const report = JSON.parse(readFileSync(join(dist, ...run.file.split('/')), 'utf8'));
    assert.match(report.runId, /\S/, `${run.id} has no runId`);
    assert.equal(report.payer.payerId, run.payerId, `${run.id} payer`);
    assert.equal(report.verdict.status, run.verdict, `${run.id} verdict`);
    assert.ok(report.steps.length > 0, `${run.id} has no steps`);
    for (const step of report.steps) {
      assert.match(step.status, /^(passed|failed|skipped)$/, `${run.id} ${step.stepId} status`);
      assert.equal(typeof step.elapsedMs, 'number');
    }
    assert.ok(Array.isArray(report.findings) && report.findings.length > 0, `${run.id} has no findings`);
    if (run.fault) {
      assert.equal(report.verdict.status, 'FAIL', `${run.id} should fail`);
      const fail = report.findings.find(f => f.severity === 'FAIL');
      assert.ok(fail.explanation && fail.suggestedFix, `${run.id} FAIL finding lacks explanation or fix`);
    } else {
      assert.notEqual(report.verdict.status, 'FAIL', `${run.id} should not fail`);
    }
  }
});

test('the bundle holds only the replay files and recorded runs', () => {
  requireBundle();
  const allowed = /^(index\.html|manifest\.json|replay\.js|replay\.css|runs\/[a-z0-9-]+\.json)$/;
  for (const file of bundleFiles()) {
    const rel = relative(dist, file).split(sep).join('/');
    assert.match(rel, allowed, `unexpected file in the bundle: ${rel}`);
  }
});

test('no token, secret or PEM pattern appears anywhere in the bundle', () => {
  requireBundle();
  const leaks = [];
  for (const file of bundleFiles()) {
    const text = readFileSync(file, 'utf8');
    const rel = relative(dist, file);
    leaks.push(...findTextLeaks(text).map(l => ({ file: rel, ...l })));
    if (file.endsWith('.json')) leaks.push(...findJsonLeaks(JSON.parse(text)).map(l => ({ file: rel, ...l })));
  }
  assert.deepEqual(leaks, []);
});

test('replay.js renders the picker, the disclaimer, the timeline and the findings', async () => {
  const manifest = requireBundle();
  const { createRoot } = installFakeDom(pathname => {
    const prefix = '/workbench/';
    if (!pathname.startsWith(prefix)) return undefined;
    const p = join(dist, ...pathname.slice(prefix.length).split('/'));
    return existsSync(p) ? readFileSync(p, 'utf8') : undefined;
  });
  const { mountReplay } = await import(pathToFileURL(join(dist, 'replay.js')).href);
  const el = createRoot();
  const replay = await mountReplay(el, { baseUrl: '/workbench' });

  assert.ok(el.textContent.includes(DISCLAIMER), 'disclaimer missing');
  assert.ok(el.textContent.includes('Pick a scenario'));
  const radios = el.findAll(n => n.tagName === 'INPUT' && n.getAttribute('type') === 'radio');
  assert.equal(radios.length, manifest.runs.length);
  assert.equal(radios[0].checked, true);

  for (const run of manifest.runs) {
    await replay.select(run.id);
    const report = JSON.parse(readFileSync(join(dist, ...run.file.split('/')), 'utf8'));
    const text = el.textContent;
    assert.ok(text.includes(DISCLAIMER), `${run.id}: disclaimer missing`);
    assert.ok(text.includes(`Showing ${run.title}.`), `${run.id}: not shown`);
    for (const step of report.steps) assert.ok(text.includes(step.title), `${run.id}: step ${step.stepId} missing`);
    for (const f of report.findings) {
      assert.ok(text.includes(f.title), `${run.id}: finding ${f.checkId} missing`);
      if (f.explanation) assert.ok(text.includes(f.explanation), `${run.id}: ${f.checkId} explanation missing`);
      if (f.suggestedFix) assert.ok(text.includes(f.suggestedFix), `${run.id}: ${f.checkId} fix missing`);
    }
    const exchanges = report.steps.flatMap(s => s.details.exchanges || []);
    const rendered = el.findAll(n => n.tagName === 'DETAILS' && n.className === 'pw-exchange');
    assert.equal(rendered.length, exchanges.length, `${run.id}: exchanges`);
    assert.equal(radios[manifest.runs.indexOf(run)].checked, true);
  }

  // Picking a scenario with the radio group switches the view.
  const last = manifest.runs.at(-1);
  await replay.select(manifest.runs[0].id);
  radios.at(-1).checked = true;
  radios.at(-1).dispatch('change');
  await new Promise(r => setTimeout(r, 10));
  assert.ok(el.textContent.includes(`Showing ${last.title}.`));
});

test('replay.js reports a missing bundle without throwing', async () => {
  requireBundle();
  const { createRoot } = installFakeDom(() => undefined);
  const { mountReplay } = await import(pathToFileURL(join(dist, 'replay.js')).href);
  const el = createRoot();
  await mountReplay(el, { baseUrl: '/nowhere/' });
  assert.ok(el.textContent.includes(DISCLAIMER));
  assert.ok(el.textContent.includes('Could not load the recorded runs (HTTP 404).'));
});
