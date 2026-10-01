// Static replay of recorded workbench runs, for embedding on a website.
// Plain DOM, no framework, no build step. The only network calls are fetches of
// this bundle's own manifest.json and runs/*.json. All recorded text goes in via
// textContent, never as HTML.
//
// Rendering is ported from workbench-app/src/main/resources/static/app.js and
// adapted to the report JSON (GET /api/runs/{id}/report?format=json), whose steps
// carry status and elapsedMs at the top level.
//
//   import { mountReplay } from './replay.js';
//   mountReplay(document.getElementById('replay'), { baseUrl: '/workbench/' });

export const DISCLAIMER =
  'Recorded run against a synthetic mock payer. Passing here does not prove real-payer interoperability.';

const SEVERITIES = ['FAIL', 'WARN', 'INFO', 'PASS'];
const VERDICT_LABELS = { PASS: 'Pass', PASS_WITH_WARNINGS: 'Pass with warnings', FAIL: 'Fail' };

let mounts = 0;

/**
 * Renders the scenario picker and the selected run into `el`.
 *
 * @param {HTMLElement} el      container; its contents are replaced
 * @param {object} [options]
 * @param {string} [options.baseUrl]       where manifest.json lives; defaults to this module's folder
 * @param {string} [options.run]           id of the run to show first; defaults to the first in the manifest
 * @param {number} [options.headingLevel]  level of the run title heading (default 2)
 * @returns {Promise<{ select(id: string): Promise<void> }>}
 */
export async function mountReplay(el, options = {}) {
  const base = new URL(options.baseUrl || '.', options.baseUrl ? document.baseURI : import.meta.url);
  if (!base.pathname.endsWith('/')) base.pathname += '/';
  const level = Math.min(Math.max(options.headingLevel || 2, 1), 4);
  const hx = offset => `h${level + offset}`;
  const uid = `pw-replay-${++mounts}`;
  const cache = new Map();
  let current = 0;

  const status = h('p', { class: 'pw-status', role: 'status', 'aria-live': 'polite' });
  const picker = h('div', { class: 'pw-picker' });
  const view = h('div', { class: 'pw-run', id: `${uid}-run` });
  el.classList.add('pw-replay');
  el.replaceChildren(
    h('p', { class: 'pw-disclaimer', role: 'note' }, DISCLAIMER),
    picker, status, view);

  status.textContent = 'Loading recorded runs…';
  let manifest;
  try {
    manifest = await getJson(new URL('manifest.json', base));
  } catch (e) {
    status.textContent = `Could not load the recorded runs (${e.message}).`;
    return { select: async () => {} };
  }
  const runs = manifest.runs || [];
  if (!runs.length) {
    status.textContent = 'This bundle has no recorded runs.';
    return { select: async () => {} };
  }

  const inputs = new Map();
  const radios = runs.map((run, i) => {
    const id = `${uid}-${i}`;
    const input = h('input', { type: 'radio', name: `${uid}-scenario`, id, value: run.id });
    input.addEventListener('change', () => input.checked && select(run.id));
    inputs.set(run.id, input);
    return h('label', { class: 'pw-choice', for: id },
      input,
      h('span', { class: 'pw-choice-text' },
        h('span', { class: 'pw-choice-title' }, run.title),
        run.verdict && h('span', { class: `pw-badge ${run.verdict}` }, VERDICT_LABELS[run.verdict] || run.verdict),
        run.description && h('span', { class: 'pw-choice-desc' }, run.description)));
  });
  picker.replaceChildren(h('fieldset', {},
    h('legend', {}, 'Pick a scenario'),
    h('div', { class: 'pw-choices' }, radios)));

  async function select(id) {
    const run = runs.find(r => r.id === id);
    if (!run) return;
    inputs.get(run.id).checked = true;
    const token = ++current;
    status.textContent = `Loading ${run.title}…`;
    try {
      if (!cache.has(run.id)) cache.set(run.id, await getJson(new URL(run.file, base)));
    } catch (e) {
      if (token !== current) return;
      status.textContent = `Could not load ${run.title} (${e.message}).`;
      view.replaceChildren();
      return;
    }
    if (token !== current) return;
    view.replaceChildren(...renderReport(run, cache.get(run.id), hx));
    status.textContent = `Showing ${run.title}.`;
  }

  const first = runs.find(r => r.id === options.run) || runs[0];
  await select(first.id);
  return { select };
}

function renderReport(run, report, hx) {
  const verdict = report.verdict || {};
  const counts = report.counts || {};
  const meta = [
    report.payer && report.payer.displayName,
    report.environment,
    report.igVersion && `CRD IG ${report.igVersion}`,
    report.startedAt && `recorded ${report.startedAt.slice(0, 10)}`,
    report.workbenchVersion && `workbench ${report.workbenchVersion}`,
  ].filter(Boolean).join(' · ');
  return [
    h(hx(0), { class: 'pw-title' }, run.title),
    h('p', { class: 'pw-meta' }, meta),
    h('div', { class: `pw-verdict ${verdict.status || ''}` },
      h('span', { class: `pw-badge ${verdict.status || ''}` }, VERDICT_LABELS[verdict.status] || verdict.status || 'Unknown'),
      h('span', {}, verdict.headline || ''),
      h('span', { class: 'pw-counts' },
        SEVERITIES.map(sev => h('span', { class: `pw-count ${sev}` }, `${counts[sev] || 0} ${sev}`)))),
    h('section', { class: 'pw-section' },
      h(hx(1), {}, 'Step timeline'),
      h('ol', { class: 'pw-steps' }, (report.steps || []).map(s => renderStep(s, hx)))),
    h('section', { class: 'pw-section' },
      h(hx(1), {}, 'Findings'),
      renderFindings(report.findings || [], hx)),
  ];
}

function renderStep(step, hx) {
  const status = step.status || 'unknown';
  const details = step.details || {};
  const exchanges = Array.isArray(details.exchanges) ? details.exchanges : [];
  const extra = Object.fromEntries(Object.entries(details).filter(([k]) => k !== 'status' && k !== 'exchanges'));
  return h('li', { class: `pw-step ${status}` },
    h('div', { class: 'pw-step-head' },
      h(hx(2), {}, step.title || step.stepId),
      h('span', { class: `pw-status-tag ${status}` }, status),
      status !== 'skipped' && h('span', { class: 'pw-latency' }, formatMs(step.elapsedMs || 0))),
    step.summary && h('p', {}, step.summary),
    exchanges.length
      ? exchanges.map(renderExchange)
      : (step.exchanges || []).map(line => h('p', { class: 'pw-mono' }, line)),
    Object.keys(extra).length > 0 && h('details', {},
      h('summary', {}, 'Step details'),
      h('div', {}, h('pre', { tabindex: '0' }, JSON.stringify(extra, null, 2)))));
}

function renderExchange(x) {
  const status = x.status ? `HTTP ${x.status}` : 'no response';
  return h('details', { class: 'pw-exchange' },
    h('summary', {}, `${x.method} ${x.url} → ${status} · ${formatMs(x.latencyMs || 0)}`),
    h('div', {},
      h('p', { class: 'pw-label' }, 'Request headers'), h('pre', { tabindex: '0' }, headers(x.requestHeaders)),
      x.requestBody && [h('p', { class: 'pw-label' }, 'Request body'), h('pre', { tabindex: '0' }, pretty(x.requestBody))],
      x.transportError && [h('p', { class: 'pw-label' }, 'Transport error'), h('pre', { tabindex: '0' }, x.transportError)],
      x.status ? [
        h('p', { class: 'pw-label' }, 'Response headers'), h('pre', { tabindex: '0' }, headers(x.responseHeaders)),
        h('p', { class: 'pw-label' }, 'Response body'),
        h('pre', { tabindex: '0' }, x.responseBody ? pretty(x.responseBody) : '(empty)'),
      ] : null,
      h('p', { class: 'pw-muted' }, 'Secrets, tokens and signatures were redacted before this run was recorded.')));
}

function renderFindings(findings, hx) {
  if (!findings.length) return h('p', { class: 'pw-muted' }, 'No findings.');
  return SEVERITIES.map(sev => {
    const group = findings.filter(f => f.severity === sev);
    if (!group.length) return null;
    const cards = group.map(f => h('article', { class: `pw-finding ${f.severity}` },
      h(hx(2), {}, f.title),
      h('code', {}, f.checkId),
      f.explanation && h('p', {}, f.explanation),
      f.evidence && h('details', {}, h('summary', {}, 'Evidence'), h('div', {}, h('pre', { tabindex: '0' }, f.evidence))),
      f.suggestedFix && h('p', { class: 'pw-fix' }, h('strong', {}, 'Fix: '), f.suggestedFix)));
    const label = [h('span', { class: `pw-badge ${sev}` }, sev), ` ${group.length} finding${group.length === 1 ? '' : 's'}`];
    // Passing checks are collapsed so failures stay in view.
    return sev === 'PASS'
      ? h('div', { class: 'pw-sev-group' }, h('details', {}, h('summary', {}, label), h('div', {}, cards)))
      : h('div', { class: 'pw-sev-group' }, h('p', { class: 'pw-sev-head' }, label), cards);
  }).filter(Boolean);
}

// ---- helpers ----

async function getJson(url) {
  const res = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/** Builds an element; children may be strings, nodes, arrays or null. */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  const add = c => {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) c.forEach(add);
    else el.append(c instanceof Node ? c : String(c));
  };
  children.forEach(add);
  return el;
}

export function formatMs(ms) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`;
}

export function headers(map) {
  return Object.entries(map || {}).map(([k, vs]) => `${k}: ${[].concat(vs).join(', ')}`).join('\n') || '(none)';
}

export function pretty(text) {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
}
