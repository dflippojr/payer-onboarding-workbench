import './live-history.test.mjs';
// Checks the exported replay bundle (site-dist/ by default, or $REPLAY_BUNDLE_DIR).
// Run scripts/export-replays.sh first, then: node --test replay/test/
import { mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { findJsonLeaks, findTextLeaks } from './leaks.mjs';
import { installFakeDom } from './fake-dom.mjs';

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const dist = resolve(process.env.REPLAY_BUNDLE_DIR || join(root, 'site-dist'));
const DISCLAIMER = 'Recorded run against a synthetic mock payer; addresses rewritten to example hosts. Passing here does not prove real-payer interoperability.';

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

test('leak scanner distinguishes auth challenges from credentials', () => {
  for (const challenge of [
    'Bearer realm="northwind", error="invalid_token", error_description="Expired"',
    'Bearer error="invalid_token"', 'Bearer error=invalid_request', 'Basic realm="payer"',
  ]) {
    assert.deepEqual(findTextLeaks(challenge), []);
    assert.deepEqual(findTextLeaks(JSON.stringify({ header: challenge })), []);
  }
  for (const credential of ['Bearer error=', 'Bearer realm=', 'Basic c3ludGhldGljOnNlY3JldA==']) {
    assert.ok(findTextLeaks(credential).some(l => l.check === 'Bearer/Basic credential'));
    assert.ok(findJsonLeaks({ requestHeaders: { Authorization: [credential] } }).length > 0);
  }
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
    assert.equal(run.payerName, report.payer.displayName, `${run.id} payerName`);
    assert.match(run.teaser, /\S/, `${run.id} has no teaser`);
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

/** Mounts the bundle's replay.js on a fake DOM; `editManifest` rewrites manifest.json on the way in. */
async function mountBundle(options = {}, { reducedMotion = false, editManifest } = {}) {
  const { createRoot } = installFakeDom(pathname => {
    const prefix = '/workbench/';
    if (!pathname.startsWith(prefix)) return undefined;
    const rel = pathname.slice(prefix.length);
    const p = join(dist, ...rel.split('/'));
    if (!existsSync(p)) return undefined;
    const body = readFileSync(p, 'utf8');
    return rel === 'manifest.json' && editManifest ? JSON.stringify(editManifest(JSON.parse(body))) : body;
  }, { reducedMotion });
  const mod = await import(pathToFileURL(join(dist, 'replay.js')).href);
  const el = createRoot();
  const replay = await mod.mountReplay(el, { baseUrl: '/workbench', ...options });
  return { el, replay, mod };
}

const readRun = run => JSON.parse(readFileSync(join(dist, ...run.file.split('/')), 'utf8'));
const findRun = id => requireBundle().runs.find(r => r.id === id);
const byClass = (el, cls) => el.findAll(n => n.className.split(' ').includes(cls));
const visibleSteps = el => byClass(el, 'pw-step').filter(n => n.getAttribute('hidden') === null);
const statusText = el => byClass(el, 'pw-status')[0].textContent;
const runButton = el => el.findAll(n => n.tagName === 'BUTTON')[0];

/** The example host each payer's local address is rewritten to by the export scripts. */
const PAYER_HOSTS = {
  'northwind-synthetic': 'https://crd.northwind-health.example',
  'fabrikam-synthetic': 'https://crd.fabrikam-benefits.example',
};

test('no localhost or 127.0.0.1 address appears anywhere in the bundle', () => {
  requireBundle();
  const hits = bundleFiles()
    .filter(file => /localhost|127\.0\.0\.1/i.test(readFileSync(file, 'utf8')))
    .map(file => relative(dist, file));
  assert.deepEqual(hits, []);
});

test('each run shows its payer at the payer\'s example host', () => {
  const manifest = requireBundle();
  for (const run of manifest.runs) {
    const report = JSON.parse(readFileSync(join(dist, ...run.file.split('/')), 'utf8'));
    const host = PAYER_HOSTS[run.payerId];
    assert.ok(host, `${run.id}: no example host for ${run.payerId}`);
    const connection = report.steps.find(s => s.stepId === 'resolve-connection').details.connection;
    assert.equal(connection.baseUrl, host, `${run.id}: baseUrl`);
    for (const x of report.steps.flatMap(s => s.details.exchanges || [])) {
      assert.ok(x.url.startsWith(`${host}/`), `${run.id}: ${x.method} ${x.url}`);
    }
  }
});

test('the rewritten JWT aud still differs from the audience Fabrikam expects, by host only', () => {
  const report = readRun(findRun('fabrikam-wrong-audience-reject'));
  const auth = report.steps.find(s => s.stepId === 'authenticate').details;
  const aud = new URL(auth.jwtClaims.aud);
  assert.equal(aud.origin, PAYER_HOSTS['fabrikam-synthetic']);
  const finding = report.findings.find(f => f.checkId === 'auth.jwt-audience');
  const expected = new URL(finding.evidence.match(/URL named in the payer's error: (\S+)/)[1]);
  assert.notEqual(expected.host, aud.host, 'the expected audience should be a different host');
  assert.equal(expected.pathname, aud.pathname);
  assert.ok(finding.explanation.includes(expected.href) || finding.explanation.includes(expected.origin),
    'the explanation should name the URL the payer expects');
});

test('in the slow run only the hook call is slow', () => {
  const report = readRun(findRun('northwind-slow-response'));
  const elapsed = Object.fromEntries(report.steps.map(s => [s.stepId, s.elapsedMs]));
  for (const id of ['discovery', 'authenticate']) {
    assert.ok(elapsed[id] < 5_000, `${id} took ${elapsed[id]} ms`);
  }
  assert.ok(elapsed['hook-request'] > 10_000, `hook-request took ${elapsed['hook-request']} ms`);
  assert.deepEqual(report.findings.filter(f => f.severity === 'FAIL').map(f => f.checkId), ['perf.latency']);
});

test('replay.js renders the picker, the disclaimer, the timeline and the findings', async () => {
  const manifest = requireBundle();
  const { el, replay } = await mountBundle();

  assert.ok(el.textContent.includes(DISCLAIMER), 'disclaimer missing');
  assert.ok(el.textContent.includes('Pick a scenario'));
  const radios = el.findAll(n => n.tagName === 'INPUT' && n.getAttribute('type') === 'radio');
  assert.equal(radios.length, manifest.runs.length);
  assert.equal(radios[0].checked, true);
  const cards = byClass(el, 'pw-choice');
  for (const [i, run] of manifest.runs.entries()) {
    assert.ok(cards[i].textContent.includes(run.title), `${run.id}: card title`);
    assert.ok(cards[i].textContent.includes(run.teaser), `${run.id}: card teaser`);
    assert.ok(cards[i].textContent.includes(run.payerName), `${run.id}: card payer`);
  }

  for (const run of manifest.runs) {
    await replay.select(run.id);
    const report = readRun(run);
    assert.ok(statusText(el).includes(`Showing ${run.title}.`), `${run.id}: not shown`);
    assert.equal(visibleSteps(el).length, 0, `${run.id}: steps shown before Run`);
    replay.showResult();
    const text = el.textContent;
    assert.ok(text.includes(DISCLAIMER), `${run.id}: disclaimer missing`);
    for (const step of report.steps) assert.ok(text.includes(step.title), `${run.id}: step ${step.stepId} missing`);
    for (const f of report.findings) {
      assert.ok(text.includes(f.title), `${run.id}: finding ${f.checkId} missing`);
      if (f.explanation) assert.ok(text.includes(f.explanation), `${run.id}: ${f.checkId} explanation missing`);
      if (f.suggestedFix) assert.ok(text.includes(f.suggestedFix), `${run.id}: ${f.checkId} fix missing`);
    }
    // Raw HTTP sits behind one "Show request/response" disclosure per step.
    const exchanges = report.steps.flatMap(s => s.details.exchanges || []);
    const rendered = byClass(el, 'pw-exchange');
    assert.equal(rendered.length, exchanges.length, `${run.id}: exchanges`);
    for (const x of rendered) {
      const box = x.parentNode.parentNode;
      assert.equal(box.tagName, 'DETAILS', `${run.id}: exchange not in a disclosure`);
      assert.equal(box.childNodes[0].textContent, 'Show request/response');
    }
    const withExchanges = report.steps.filter(s => (s.details.exchanges || []).length).length;
    assert.equal(byClass(el, 'pw-step-details').filter(d => d.childNodes[0].textContent === 'Show request/response').length,
      withExchanges, `${run.id}: one disclosure per step`);
    assert.equal(radios[manifest.runs.indexOf(run)].checked, true);
  }

  // Picking a scenario with the radio group switches the view.
  const last = manifest.runs.at(-1);
  await replay.select(manifest.runs[0].id);
  radios.at(-1).checked = true;
  radios.at(-1).dispatch('change');
  await new Promise(r => setTimeout(r, 10));
  assert.ok(statusText(el).includes(`Showing ${last.title}.`));
});

test('step durations follow the documented clamp and total cap', async () => {
  requireBundle();
  const { mod } = await mountBundle();
  const { TIMING, stepDurations } = mod;
  assert.deepEqual(TIMING, { scale: 0.25, minMs: 350, maxMs: 1200, totalMs: 6000 });
  assert.deepEqual(stepDurations([{ elapsedMs: 2 }, { elapsedMs: 2000 }, { elapsedMs: 11005 }]), [350, 500, 1200]);
  const long = stepDurations(Array.from({ length: 10 }, () => ({ elapsedMs: 9000 })));
  assert.ok(long.reduce((a, b) => a + b, 0) <= 6000, 'whole run must fit in about 6 s');
});

test('Run plays the steps in order, then stops at the failing step', async () => {
  const run = findRun('fabrikam-wrong-audience-reject');
  const report = readRun(run);
  const { el, mod } = await mountBundle({ run: run.id });
  const stop = report.steps.findIndex(s => s.title === report.verdict.brokeAt);
  assert.ok(stop > 0 && stop < report.steps.length - 1, 'the run should break mid-flow');
  const durations = mod.stepDurations(report.steps.slice(0, stop + 1));

  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    assert.ok(runButton(el).textContent.startsWith('Run'));
    runButton(el).dispatch('click');
    for (let i = 0; i <= stop; i++) {
      const shown = visibleSteps(el);
      assert.equal(shown.length, i + 1, `step ${i} revealed alone`);
      assert.equal(shown[i].className, 'pw-step active');
      assert.ok(shown[i].textContent.includes(report.steps[i].title));
      for (let j = 0; j < i; j++) assert.equal(shown[j].className, `pw-step ${report.steps[j].status}`);
      assert.equal(byClass(el, 'pw-result').length, 0, 'result shown before the run ended');
      assert.equal(statusText(el), `Replaying ${run.title}…`, 'announced once, not per step');
      assert.equal(runButton(el).getAttribute('disabled'), null, 'Run must keep keyboard focus while playing');
      mock.timers.tick(durations[i]);
    }
    const steps = visibleSteps(el);
    assert.equal(steps.length, report.steps.length);
    assert.equal(steps[stop].className, 'pw-step failed');
    assert.ok(steps[stop].textContent.includes('✗ failed'), 'failure needs an icon and text');
    for (const later of steps.slice(stop + 1)) assert.match(later.className, /\bpw-after\b/);
    assert.ok(report.steps.slice(stop + 1).some(s => s.status === 'skipped'));
    assert.equal(byClass(el, 'pw-result').length, 1);
    assert.ok(runButton(el).textContent.startsWith('Replay'));
    assert.equal(statusText(el), `${run.title}: onboarding would fail. ${report.findings.find(f => f.severity === 'FAIL').title}.`);
  } finally {
    mock.timers.reset();
  }
});

test('the result card leads with the first failure, or says a healthy run would succeed', async () => {
  const manifest = requireBundle();
  const { el, replay } = await mountBundle();
  for (const run of manifest.runs) {
    await replay.select(run.id);
    replay.showResult();
    const report = readRun(run);
    const [card] = byClass(el, 'pw-result');
    assert.ok(card, `${run.id}: no result card`);
    const view = byClass(el, 'pw-run')[0];
    assert.equal(view.childNodes.indexOf(card.parentNode), 3, `${run.id}: card is not above the timeline`);
    const fails = report.findings.filter(f => f.severity === 'FAIL');
    if (fails.length) {
      assert.match(card.className, /\bFAIL\b/);
      const [first] = fails;
      assert.equal(byClass(card, 'pw-result-title')[0].textContent, first.title);
      for (const part of [first.explanation, first.suggestedFix, first.checkId]) {
        assert.ok(card.textContent.includes(part), `${run.id}: card lacks ${part}`);
      }
      const more = fails.length - 1;
      assert.equal(card.textContent.includes(`+${more} more failing check`), more > 0, `${run.id}: +N more`);
    } else {
      assert.equal(byClass(card, 'pw-result-title')[0].textContent, 'Onboarding would succeed');
      for (const s of report.steps) assert.ok(card.textContent.includes(s.title), `${run.id}: ${s.title} not named`);
    }
    const passed = report.findings.filter(f => f.severity === 'PASS').length;
    const [collapse] = byClass(el, 'pw-passed');
    assert.equal(collapse.tagName, 'DETAILS');
    assert.equal(collapse.childNodes[0].textContent, `✓ ${passed} check${passed === 1 ? '' : 's'} passed`);
    assert.equal(collapse.findAll(n => n.tagName === 'LI').length, passed);
  }
});

test('a slow payer fills a latency bar past the recorded budget, labelled with the real ms', async () => {
  const run = findRun('northwind-slow-response');
  const report = readRun(run);
  const { el, replay, mod } = await mountBundle({ run: run.id });
  const info = mod.latencyInfo(report);
  assert.equal(report.steps[info.step].stepId, 'hook-request');
  assert.ok(info.ms > info.failMs, 'the slow run should be over the fail budget');
  replay.showResult();
  const [bar] = byClass(el, 'pw-bar');
  assert.ok(visibleSteps(el)[info.step].findAll(n => n === bar).length, 'bar is not on the slow step');
  assert.ok(bar.textContent.includes(`${info.ms.toLocaleString('en-US')} ms recorded, over the 10 s fail budget`), bar.textContent);
  const pct = v => parseFloat(v);
  const fill = byClass(bar, 'pw-bar-fill')[0].style['--pw-fill'];
  const failMark = byClass(bar, 'fail')[0].style.left;
  assert.ok(pct(fill) > pct(failMark) && pct(fill) <= 100, `fill ${fill} should overshoot the fail mark at ${failMark}`);
});

test('under reduced motion, Run shows the final state at once', async () => {
  const run = findRun('fabrikam-wrong-audience-reject');
  const report = readRun(run);
  const { el } = await mountBundle({ run: run.id }, { reducedMotion: true });
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    runButton(el).dispatch('click');
    assert.equal(visibleSteps(el).length, report.steps.length);
    assert.equal(byClass(el, 'active').length, 0, 'no step should be pulsing');
    assert.equal(byClass(el, 'pw-result').length, 1);
    assert.ok(statusText(el).startsWith(`${run.title}: onboarding would fail.`));
  } finally {
    mock.timers.reset();
  }
});

test('options.autoplay plays a run as soon as it is picked', async () => {
  const run = findRun('northwind-healthy');
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    const { el, replay } = await mountBundle({ run: run.id, autoplay: true });
    assert.equal(statusText(el), `Replaying ${run.title}…`);
    assert.equal(visibleSteps(el).length, 1);
    replay.showResult();
    assert.equal(statusText(el), `${run.title}: onboarding would succeed.`);
    assert.equal(byClass(el, 'pw-result-title')[0].textContent, 'Onboarding would succeed');
  } finally {
    mock.timers.reset();
  }
});

test('without a manifest teaser, the card falls back to the first FAIL finding', async () => {
  const manifest = requireBundle();
  const strip = m => ({ ...m, runs: m.runs.map(({ teaser, payerName, ...run }) => run) });
  const { el, mod } = await mountBundle({}, { editManifest: strip });
  await new Promise(r => setTimeout(r, 20));
  const cards = byClass(el, 'pw-choice');
  for (const [i, run] of manifest.runs.entries()) {
    const report = readRun(run);
    const fail = report.findings.find(f => f.severity === 'FAIL');
    const expected = fail ? fail.title : 'Healthy connection';
    assert.equal(mod.teaserFor({ ...run, teaser: undefined }, report), expected);
    assert.equal(byClass(cards[i], 'pw-choice-teaser')[0].textContent, expected, `${run.id}: teaser`);
    assert.equal(byClass(cards[i], 'pw-choice-payer')[0].textContent, report.payer.displayName, `${run.id}: payer`);
  }
  assert.equal(mod.teaserFor({ teaser: 'Payer is slow' }, null), 'Payer is slow');
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

test('vendor-into-site.mjs copies the bundle and drops stale runs', () => {
  requireBundle();
  const target = mkdtempSync(join(tmpdir(), 'pw-vendor-'));
  try {
    mkdirSync(join(target, 'runs'));
    writeFileSync(join(target, 'runs', 'stale-run.json'), '{}');
    writeFileSync(join(target, 'keep.txt'), 'site file');
    execFileSync(process.execPath, [join(root, 'scripts', 'vendor-into-site.mjs'), target], { stdio: 'pipe' });
    const rel = dir => bundleFiles(dir).map(f => relative(dir, f)).sort();
    assert.deepEqual(rel(target), [...rel(dist), 'keep.txt'].sort());
    for (const file of bundleFiles()) {
      assert.equal(readFileSync(join(target, relative(dist, file)), 'utf8'), readFileSync(file, 'utf8'));
    }
    assert.throws(() => execFileSync(process.execPath, [join(root, 'scripts', 'vendor-into-site.mjs'), root], { stdio: 'pipe' }));
  } finally {
    rmSync(target, { recursive: true, force: true });
  }
});
