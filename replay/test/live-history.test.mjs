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

async function load(history, override = () => undefined) {
  const elements = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(m => [m[1], new Element()]));
  const $ = id => elements[id];
  $('run-form').append($('payers'), $('faults'));
  $('environment').value = 'SANDBOX';
  $('report-format').value = 'html';
  $('report-actions').hidden = true;
  const requests = [];
  const fetch = async (path, options) => {
    requests.push({ path, method: options?.method || 'GET' });
    const changed = await override(path, options);
    if (changed) return changed;
    const data = {
      'api/payers': [{ payerId: 'synthetic-payer', displayName: 'Synthetic Payer', connections: [], faults: [] }],
      'api/samples': [{ id: 'synthetic-sample', title: 'Synthetic request', hook: 'order-sign' }],
      'api/features': {},
      'api/runs': options?.method === 'POST' ? runFixture('new') : history,
    };
    return { ok: true, status: 200, json: async () => data[path] || runFixture(path.split('/').at(-1)) };
  };
  runInNewContext(app, { document: { getElementById: $, createElement: tag => new Element(tag) }, Node: Element, fetch });
  await settle();
  $('sample').value = 'synthetic-sample';
  return { $, requests };
}

async function choose(ui, id) {
  ui.$('recent-runs').value = id;
  await ui.$('recent-runs').dispatch('change');
}

const errorResponse = status => ({ ok: false, status, json: async () => ({ detail: 'Synthetic error' }) });

test('reopens older run with findings and report, preserves settings, and survives page refresh without POST', async () => {
  for (let refresh = 0; refresh < 2; refresh++) {
    const ui = await load([summary('newer'), summary('older')]);
    assert.match(ui.$('recent-runs').textContent, /synthetic-payer.*SANDBOX.*2026-10-01.*PASS_WITH_WARNINGS/);
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
  assert.match(html, /<label class="field">Recent runs\s*<select id="recent-runs" aria-describedby="history-status">/);
  assert.match(html, /id="history-status"[^>]*role="status"[^>]*aria-live="polite"/);
});
