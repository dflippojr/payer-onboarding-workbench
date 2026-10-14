// Live UI history regression tests: synthetic fixtures, no browser dependencies or payer calls.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const app = readFileSync(new URL('../../workbench-app/src/main/resources/static/app.js', import.meta.url), 'utf8');
const html = readFileSync(new URL('../../workbench-app/src/main/resources/static/index.html', import.meta.url), 'utf8');

class Element {
  constructor(tag = 'div') {
    this.tag = tag;
    this.children = [];
    this.attributes = {};
    this.listeners = {};
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  set textContent(text) { this.children = [String(text)]; }
  get textContent() { return this.children.map(c => c instanceof Element ? c.textContent : c).join(''); }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
    if (name === 'value') this.value = String(value);
    if (name === 'checked') this.checked = true;
  }
  removeAttribute(name) { delete this.attributes[name]; if (name === 'href') delete this.href; }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  async dispatch(type) { await this.listeners[type]?.({ preventDefault() {} }); }
  focus() { this.focused = true; }
  closest() { return new Element('label'); }
  descendants() { return this.children.filter(c => c instanceof Element).flatMap(c => [c, ...c.descendants()]); }
  querySelectorAll(selector) {
    const name = /name="([^"]+)"/.exec(selector)?.[1];
    return this.descendants().filter(c => c.attributes.name === name && (!selector.includes(':checked') || c.checked));
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0]; }
}

const runFixture = id => ({ runId: id, payerId: 'synthetic-payer', environment: 'SANDBOX',
  steps: [{ stepId: 'discovery', details: { status: 'passed' }, elapsed: 0.01, summary: `step ${id}` }],
  findings: [{ severity: 'WARN', title: `finding ${id}`, checkId: 'synthetic.warning' }] });
const summary = id => ({ runId: id, payerId: 'synthetic-payer', environment: 'SANDBOX',
  startedAt: '2026-10-01T12:00:00Z', verdict: 'PASS_WITH_WARNINGS' });
const settle = async () => { for (let i = 0; i < 15; i++) await new Promise(resolve => setImmediate(resolve)); };

async function load(history, override = () => undefined, customEnabled = false) {
  const elements = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(m => [m[1], new Element()]));
  const $ = id => elements[id];
  $('run-form').append($('payers'), $('faults'));
  $('environment').value = 'SANDBOX';
  $('report-format').value = 'html';
  $('report-actions').hidden = true;
  const requests = [];
  const fetch = async (path, options) => {
    requests.push({ path, method: options?.method || 'GET', body: options?.body });
    const changed = await override(path, options);
    if (changed) return changed;
    const data = {
      'api/payers': [{ payerId: 'synthetic-payer', displayName: 'Synthetic Payer', connections: [], faults: [] }],
      'api/samples': [{ id: 'synthetic-sample', title: 'Synthetic request', hook: 'order-sign' }],
      'api/features': { customEndpoints: customEnabled },
      'api/runs': options?.method === 'POST' ? runFixture('new') : history,
    };
    return { ok: true, status: 200, json: async () => data[path] || runFixture(path.split('/').at(-1)) };
  };
  const context = { document: { getElementById: $, createElement: tag => new Element(tag),
    createElementNS: (ns, tag) => new Element(tag) }, Node: Element, fetch };
  runInNewContext(app, context);
  await settle();
  $('sample').value = 'synthetic-sample';
  return { $, requests, compareRuns: context.PayerWorkbench.compareRuns };
}

async function choose(ui, id) {
  ui.$('recent-runs').value = id;
  await ui.$('recent-runs').dispatch('change');
}

const errorResponse = status => ({ ok: false, status, json: async () => ({ detail: 'Synthetic error' }) });

test('reopens older run with findings and report, preserves settings, and survives page refresh without POST', async () => {
  for (let refresh = 0; refresh < 2; refresh++) {
    const ui = await load([summary('newer'), summary('older')]);
    assert.match(ui.$('recent-runs').textContent, /12:00:00 · Synthetic · SANDBOX · Warn/);
    ui.$('environment').value = 'STAGING';
    ui.$('clientId').value = 'edited-client';
    ui.$('baseUrlSuffix').value = '/edited';
    await choose(ui, 'older');
    assert.match(ui.$('steps').textContent, /step older/);
    assert.match(ui.$('findings').textContent, /finding older/);
    assert.equal(ui.$('report-link').href, 'api/runs/older/report?format=html');
    assert.equal(ui.$('report-actions').hidden, false);
    assert.equal(ui.$('environment').value, 'STAGING');
    assert.equal(ui.$('clientId').value, 'edited-client');
    assert.equal(ui.$('baseUrlSuffix').value, '/edited');
    assert.ok(ui.requests.every(r => r.method === 'GET'));
    assert.equal(ui.$('history-status').textContent, 'Run reopened.');
  }
});

test('run labels fall back to the short run id and the payer id, and name custom runs Custom', async () => {
  const ui = await load([
    { ...summary('nosteps'), startedAt: null, verdict: 'FAIL' },
    { ...summary('unknown'), payerId: 'retired-payer', verdict: 'PASS' },
    { ...summary('custom'), payerId: 'custom-endpoint', environment: 'STAGING' },
  ]);
  assert.deepEqual(ui.$('recent-runs').children.slice(1).map(o => o.textContent), [
    'run nosteps · Synthetic · SANDBOX · Fail',
    '12:00:00 · retired-payer · SANDBOX · Pass',
    '12:00:00 · Custom · STAGING · Warn',
  ]);
});

test('empty history is understandable and successful POST refreshes the collection', async () => {
  const ui = await load([]);
  assert.match(ui.$('recent-runs').textContent, /No recent runs yet/);
  assert.match(ui.$('history-status').textContent, /Run onboarding/);
  await ui.$('run-form').dispatch('submit');
  assert.equal(ui.requests.filter(r => r.method === 'POST').length, 1);
  assert.equal(ui.requests.filter(r => r.path === 'api/runs' && r.method === 'GET').length, 2);
  assert.equal(ui.$('run-button').disabled, false);
});

test('evicted selection refreshes history, announces error and clears stale report and result', async () => {
  const ui = await load([summary('older')], path => path === 'api/runs/gone' ? errorResponse(404) : undefined);
  await choose(ui, 'older');
  await choose(ui, 'gone');
  assert.match(ui.$('history-status').textContent, /no longer available/);
  assert.equal(ui.$('report-actions').hidden, true);
  assert.equal(ui.$('report-link').href, undefined);
  assert.equal(ui.$('steps').textContent, '');
  assert.equal(ui.$('findings').textContent, '');
  assert.equal(ui.requests.filter(r => r.path === 'api/runs').length, 2);
  assert.ok(ui.requests.every(r => r.method === 'GET'));
});

test('failed initial and post-run collection fetches leave form usable', async () => {
  const ui = await load([], (path, options) => path === 'api/runs' && !options ? errorResponse(503) : undefined);
  assert.match(ui.$('history-status').textContent, /Could not load recent runs/);
  await ui.$('run-form').dispatch('submit');
  assert.equal(ui.requests.filter(r => r.method === 'POST').length, 1);
  assert.equal(ui.$('run-button').disabled, false);
  assert.equal(ui.$('report-link').href, 'api/runs/new/report?format=html');
});

test('network retrieval errors are announced and do not disable form', async () => {
  const ui = await load([summary('older')], path => { if (path === 'api/runs/older') throw new Error('offline'); });
  await choose(ui, 'older');
  assert.match(ui.$('history-status').textContent, /Could not reopen run: offline/);
  await ui.$('run-form').dispatch('submit');
  assert.equal(ui.$('run-button').disabled, false);
});

test('stale response from an earlier selection cannot replace the latest result', async () => {
  let resolve;
  const pending = new Promise(done => { resolve = done; });
  const ui = await load([summary('older'), summary('newer')], path => path === 'api/runs/older' ? pending : undefined);
  const earlier = choose(ui, 'older');
  await choose(ui, 'newer');
  resolve({ ok: true, json: async () => runFixture('older') });
  await earlier;
  assert.match(ui.$('findings').textContent, /finding newer/);
});

test('selector uses native keyboard controls, accessible label and live status', () => {
  assert.match(html, /<label class="field grow">Recent runs\s*<select id="recent-runs" aria-describedby="history-status">/);
  assert.match(html, /<label class="field grow">Compare with\s*<select id="compare-runs" aria-describedby="history-status" disabled>/);
  assert.match(html, /id="history-status"[^>]*role="status"[^>]*aria-live="polite"/);
});

test('SMART custom auth shows token endpoint and key id and submits the required fields', async () => {
  assert.match(html, /<option value="OAUTH2_PRIVATE_KEY_JWT">SMART Backend Services \(private_key_jwt\)<\/option>/);
  const ui = await load([], () => undefined, true);
  const radios = ui.$('run-form').querySelectorAll('input[name="payerId"]');
  radios.forEach(radio => { radio.checked = radio.value === '__custom__'; });
  await radios.find(radio => radio.checked).dispatch('change');
  assert.equal(ui.$('custom-endpoint').hidden, false);
  ui.$('customAuthType').value = 'OAUTH2_PRIVATE_KEY_JWT';
  await ui.$('customAuthType').dispatch('change');
  assert.equal(ui.$('customTokenEndpointField').hidden, false);
  assert.equal(ui.$('customKeyIdField').hidden, false);
  assert.equal(ui.$('customCredentialField').hidden, false);
  const fields = { customBaseUrl: 'http://127.0.0.1:18090', customClientId: 'synthetic-client',
    customTokenEndpoint: 'http://127.0.0.1:18090/oauth/token', customKeyId: 'synthetic-kid',
    customCredential: '<synthetic test credential>' };
  Object.entries(fields).forEach(([id, value]) => { ui.$(id).value = value; });
  await ui.$('run-form').dispatch('submit');
  const request = JSON.parse(ui.requests.find(r => r.method === 'POST').body);
  assert.deepEqual(request.customEndpoint, { baseUrl: fields.customBaseUrl, authType: 'OAUTH2_PRIVATE_KEY_JWT',
    clientId: fields.customClientId, tokenEndpoint: fields.customTokenEndpoint,
    keyId: fields.customKeyId, credential: fields.customCredential });
  assert.deepEqual(request.faults, []);
  for (const [auth, tokenHidden, keyHidden, credentialHidden] of [
    ['NONE', true, true, true], ['OAUTH2_CLIENT_CREDENTIALS', false, true, false],
    ['CDS_HOOKS_JWT', true, false, false], ['OAUTH2_PRIVATE_KEY_JWT', false, false, false]]) {
    ui.$('customAuthType').value = auth;
    await ui.$('customAuthType').dispatch('change');
    assert.equal(ui.$('customTokenEndpointField').hidden, tokenHidden);
    assert.equal(ui.$('customKeyIdField').hidden, keyHidden);
    assert.equal(ui.$('customCredentialField').hidden, credentialHidden);
  }
});

test('custom endpoint form and picker remain hidden when feature is disabled', async () => {
  assert.match(html, /<fieldset id="custom-endpoint"[^>]* hidden>/);
  const ui = await load([]);
  assert.equal(ui.$('custom-endpoint').hidden, true);
  assert.ok(ui.$('run-form').querySelectorAll('input[name="payerId"]').every(r => r.value !== '__custom__'));
});

const STEPS = ['resolve-connection', 'discovery', 'authenticate', 'hook-request', 'parse-response', 'diagnostics'];
function stepStatus(index, broke) {
  const at = STEPS.indexOf(broke);
  if (at < 0 || index < at) return 'passed';
  return index === at || STEPS[index] === 'diagnostics' ? 'failed' : 'skipped';
}
const flow = (id, findings, broke) => ({ runId: id, payerId: 'synthetic-payer', environment: 'SANDBOX',
  steps: STEPS.map((stepId, i) => ({ stepId, details: { status: stepStatus(i, broke) }, elapsed: 0.01, summary: `${stepId} ${id}` })),
  findings: Object.entries(findings).flatMap(([checkId, severities]) =>
    [].concat(severities).map(severity => ({ severity, checkId, title: `${checkId} title` }))) });
const plain = value => JSON.parse(JSON.stringify(value));
const ids = list => list.map(c => `${c.checkId}:${c.before}->${c.after}`);

test('comparison of identical runs leaves every check unchanged', async () => {
  const { compareRuns } = await load([]);
  const run = flow('same', { 'a.pass': 'PASS', 'b.warn': 'WARN', 'c.info': 'INFO' });
  const diff = plain(compareRuns(run, run));
  assert.deepEqual(diff.verdict, { before: 'PASS_WITH_WARNINGS', after: 'PASS_WITH_WARNINGS', change: 'unchanged' });
  assert.deepEqual(diff.brokeAt, { before: null, after: null });
  assert.deepEqual(diff.steps, []);
  assert.deepEqual(diff.worse, []);
  assert.deepEqual(diff.better, []);
  assert.deepEqual(diff.oneSided, []);
  assert.deepEqual(ids(diff.unchanged), ['b.warn:WARN->WARN', 'c.info:INFO->INFO', 'a.pass:PASS->PASS']);
});

test('comparison groups a fixed FAIL, a new FAIL, WARN to FAIL and FAIL to PASS in severity order', async () => {
  const { compareRuns } = await load([]);
  const before = flow('before', { 'fixed.fail': 'FAIL', 'warn.to.fail': 'WARN', 'new.fail': 'PASS',
    'fail.to.warn': 'FAIL', 'same.warn': 'WARN' });
  const after = flow('after', { 'fixed.fail': 'PASS', 'warn.to.fail': 'FAIL', 'new.fail': 'FAIL',
    'fail.to.warn': 'WARN', 'same.warn': 'WARN' });
  const diff = plain(compareRuns(before, after));
  assert.deepEqual(diff.verdict, { before: 'FAIL', after: 'FAIL', change: 'unchanged' });
  assert.deepEqual(ids(diff.worse), ['warn.to.fail:WARN->FAIL', 'new.fail:PASS->FAIL']);
  assert.deepEqual(ids(diff.better), ['fail.to.warn:FAIL->WARN', 'fixed.fail:FAIL->PASS']);
  assert.deepEqual(ids(diff.unchanged), ['same.warn:WARN->WARN']);
  assert.equal(diff.worse[1].title, 'new.fail title');
});

test('comparison lists a check reported by only one run separately, not as better, worse or unchanged', async () => {
  const { compareRuns } = await load([]);
  const before = flow('before', { 'gone.fail': 'FAIL', 'gone.pass': 'PASS', 'same.pass': 'PASS' });
  const after = flow('after', { 'added.warn': 'WARN', 'added.pass': 'PASS', 'same.pass': 'PASS' });
  const diff = plain(compareRuns(before, after));
  assert.deepEqual(diff.worse, []);
  assert.deepEqual(diff.better, []);
  assert.deepEqual(ids(diff.unchanged), ['same.pass:PASS->PASS']);
  assert.deepEqual(ids(diff.oneSided),
    ['gone.fail:FAIL->null', 'added.warn:null->WARN', 'added.pass:null->PASS', 'gone.pass:PASS->null']);
  assert.deepEqual(diff.verdict, { before: 'FAIL', after: 'PASS_WITH_WARNINGS', change: 'better' });
});

test('comparison uses the most severe finding when a check has several', async () => {
  const { compareRuns } = await load([]);
  const before = flow('before', { 'multi.check': ['PASS', 'WARN', 'INFO'] });
  const after = flow('after', { 'multi.check': ['PASS', 'FAIL', 'WARN'] });
  assert.deepEqual(ids(plain(compareRuns(before, after)).worse), ['multi.check:WARN->FAIL']);
  assert.deepEqual(ids(plain(compareRuns(after, after)).unchanged), ['multi.check:FAIL->FAIL']);
});

test('comparison reports the broke-at step moving or disappearing and the steps that changed', async () => {
  const { compareRuns } = await load([]);
  const healthy = flow('healthy', { 'x.pass': 'PASS' });
  const discovery = flow('discovery', { 'discovery.reachable': 'FAIL' }, 'discovery');
  const auth = flow('auth', { 'auth.token': 'FAIL' }, 'authenticate');
  const moved = plain(compareRuns(discovery, auth));
  assert.deepEqual(moved.brokeAt, { before: 'discovery', after: 'authenticate' });
  assert.deepEqual(moved.steps, [
    { stepId: 'discovery', before: 'failed', after: 'passed' },
    { stepId: 'authenticate', before: 'skipped', after: 'failed' }]);
  const fixed = plain(compareRuns(discovery, healthy));
  assert.deepEqual(fixed.brokeAt, { before: 'discovery', after: null });
  assert.deepEqual(fixed.verdict, { before: 'FAIL', after: 'PASS', change: 'better' });
  assert.equal(fixed.steps.length, 5);
  assert.deepEqual(fixed.better, []);
  assert.deepEqual(ids(fixed.oneSided), ['discovery.reachable:FAIL->null', 'x.pass:null->PASS']);
  const broken = plain(compareRuns(healthy, discovery));
  assert.deepEqual(broken.brokeAt, { before: null, after: 'discovery' });
  assert.deepEqual(broken.verdict, { before: 'PASS', after: 'FAIL', change: 'worse' });
  assert.deepEqual(broken.worse, []);
  assert.deepEqual(ids(broken.oneSided), ['discovery.reachable:null->FAIL', 'x.pass:PASS->null']);
  assert.equal(plain(compareRuns(healthy, flow('no-findings', {}, 'hook-request'))).verdict.after, 'FAIL');
});

const compareHistory = [summary('shown'), summary('baseline'), summary('other')];
const ok = run => ({ ok: true, json: async () => run });
const compareRoutes = extra => path => {
  const changed = extra?.(path);
  if (changed) return changed;
  if (path === 'api/runs/shown') return ok(flow('shown', { 'discovery.reachable': 'FAIL', 'new.check': 'WARN' }, 'discovery'));
  if (path === 'api/runs/baseline') return ok(flow('baseline', { 'discovery.reachable': 'PASS', 'old.check': 'INFO' }));
  return undefined;
};
async function pick(ui, id) {
  ui.$('compare-runs').value = id;
  await ui.$('compare-runs').dispatch('change');
}

test('compare select is enabled once a run is shown and renders the changes section', async () => {
  const ui = await load(compareHistory, compareRoutes());
  assert.equal(ui.$('compare-runs').disabled, true);
  await choose(ui, 'shown');
  assert.equal(ui.$('compare-runs').disabled, false);
  assert.deepEqual(ui.$('compare-runs').children.map(o => o.attributes.value), ['', 'baseline', 'other']);
  await pick(ui, 'baseline');
  assert.equal(ui.$('comparison').hidden, false);
  assert.equal(ui.$('comparison-heading').textContent, 'Changes since run baseline');
  assert.equal(ui.$('comparison-note').textContent,
    'Earlier run 12:00:00 UTC (Pass) compared with the run on screen, 12:00:00 UTC (Fail)');
  const text = ui.$('comparison-body').textContent;
  assert.match(text, /^VerdictPass → Fail WorseBroke atevery step passed → Discovery/);
  assert.match(text, /Steps that changedDiscovery, Run diagnostics Passed → Failed/);
  assert.match(text, /Authenticate, Send sample hook request, Parse response Passed → Skipped/);
  assert.match(text, /Checks that changedCheckEarlier runThis runChangediscovery\.reachable title discovery\.reachablePassFailNewly failing/);
  assert.match(text, /Fixed or better: none\. Unchanged: none\./);
  assert.match(text, /Only in one run · 2 checksThese checks ran in only one of the two runs, usually because a step was skipped\./);
  assert.match(text, /new\.check title new\.checkThis run onlyWarnold\.check title old\.checkEarlier run onlyInfo$/);
  // The one-sided group starts collapsed.
  const oneSided = ui.$('comparison-body').descendants().find(e => e.tag === 'details');
  assert.equal(oneSided.attributes.open, undefined);
  assert.equal(ui.$('history-status').textContent, 'Comparison shown.');
  assert.ok(ui.requests.every(r => r.method === 'GET'));
  await choose(ui, 'baseline');
  assert.equal(ui.$('comparison').hidden, true);
  assert.deepEqual(ui.$('compare-runs').children.map(o => o.attributes.value), ['', 'shown', 'other']);
});

test('Stop comparing clears the comparison, says so and returns focus to Compare with', async () => {
  const ui = await load(compareHistory, compareRoutes());
  await choose(ui, 'shown');
  await pick(ui, 'baseline');
  assert.equal(ui.$('comparison').hidden, false);
  await ui.$('stop-comparing').dispatch('click');
  assert.equal(ui.$('comparison').hidden, true);
  assert.equal(ui.$('comparison-body').textContent, '');
  assert.equal(ui.$('compare-runs').value, '');
  assert.equal(ui.$('compare-runs').focused, true);
  assert.equal(ui.$('history-status').textContent, 'Comparison closed.');
});

test('comparison names unchanged checks and labels a later baseline run', async () => {
  const history = [{ ...summary('shown'), startedAt: '2026-10-01T12:00:00Z' },
    { ...summary('baseline'), startedAt: '2026-10-01T12:05:30.5Z' }];
  const ui = await load(history, path => {
    if (path === 'api/runs/shown') return ok(flow('shown', { 'a.pass': 'PASS', 'b.warn': 'WARN', 'c.fail': 'FAIL' }, 'hook-request'));
    if (path === 'api/runs/baseline') return ok(flow('baseline', { 'a.pass': 'PASS', 'b.warn': 'WARN', 'c.fail': 'WARN' }, 'hook-request'));
    return undefined;
  });
  await choose(ui, 'shown');
  await pick(ui, 'baseline');
  assert.equal(ui.$('comparison-note').textContent,
    'Later run 12:05:30 UTC (Fail) compared with the run on screen, 12:00:00 UTC (Fail)');
  const text = ui.$('comparison-body').textContent;
  assert.match(text, /^VerdictFail → Fail UnchangedBroke atSend sample hook request Unchanged/);
  assert.match(text, /No step changed status\./);
  assert.match(text, /CheckLater runThis runChangec\.fail title c\.failWarnFailNewly failing/);
  assert.match(text, /Fixed or better: none\. Unchanged: 2 checks \(b\.warn title, a\.pass title\)\.$/);
  assert.ok(!/Only in one run/.test(text));
});

test('evicted comparison run refreshes history, clears the comparison and says so', async () => {
  const ui = await load(compareHistory, compareRoutes(path => path === 'api/runs/other' ? errorResponse(404) : undefined));
  await choose(ui, 'shown');
  await pick(ui, 'baseline');
  await pick(ui, 'other');
  assert.equal(ui.$('comparison').hidden, true);
  assert.equal(ui.$('comparison-body').textContent, '');
  assert.equal(ui.$('compare-runs').value, '');
  assert.match(ui.$('history-status').textContent, /^That run is no longer available/);
  assert.equal(ui.requests.filter(r => r.path === 'api/runs').length, 2);
  assert.match(ui.$('findings').textContent, /discovery\.reachable/);
});

test('stale comparison fetch is ignored after a newer selection, a reopen or a new run', async () => {
  let resolve;
  const late = () => resolve(ok(flow('other', { 'late.fail': 'FAIL' })));
  const ui = await load(compareHistory, compareRoutes(path =>
    path === 'api/runs/other' ? new Promise(done => { resolve = done; }) : undefined));
  await choose(ui, 'shown');
  let earlier = pick(ui, 'other');
  await pick(ui, 'baseline');
  late();
  await earlier;
  assert.equal(ui.$('comparison-heading').textContent, 'Changes since run baseline');
  assert.doesNotMatch(ui.$('comparison-body').textContent, /late\.fail/);
  earlier = pick(ui, 'other');
  await choose(ui, 'baseline');
  late();
  await earlier;
  assert.equal(ui.$('comparison').hidden, true);
  await choose(ui, 'shown');
  earlier = pick(ui, 'other');
  await ui.$('run-form').dispatch('submit');
  late();
  await earlier;
  assert.equal(ui.$('comparison').hidden, true);
  assert.equal(ui.$('compare-runs').disabled, false);
});
