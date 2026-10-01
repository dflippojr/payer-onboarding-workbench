// Static replay of recorded workbench runs, for embedding on a website.
// Plain DOM, no framework, no build step. The only network calls are fetches of
// this bundle's own manifest.json and runs/*.json. All recorded text goes in via
// textContent, never as HTML.
//
// Picking a scenario shows a Run button; Run plays the recorded steps back one at a
// time, stops at the step where the flow broke, then leads with a result card.
// Under prefers-reduced-motion, Run shows the final state at once.
//
// Rendering is adapted from workbench-app/src/main/resources/static/app.js to the
// report JSON (GET /api/runs/{id}/report?format=json), whose steps carry status and
// elapsedMs at the top level.
//
//   import { mountReplay } from './replay.js';
//   mountReplay(document.getElementById('replay'), { baseUrl: '/workbench/' });

export const DISCLAIMER =
  'Recorded run against a synthetic mock payer. Passing here does not prove real-payer interoperability.';

/**
 * Playback timing. Each step lasts clamp(recorded ms × scale, minMs, maxMs); if the
 * steps add up to more than totalMs, all of them are shortened in proportion. Most
 * recorded steps take a few ms and get the minimum; an 11 s slow-payer call gets the
 * maximum. The real milliseconds are always shown as text, never just implied by speed.
 */
export const TIMING = { scale: 0.25, minMs: 350, maxMs: 1200, totalMs: 6000 };

/** perf.latency defaults (LatencyCheck), used when the recorded finding does not state them. */
const LATENCY_BUDGET = { warnMs: 5000, failMs: 10000 };

const SEVERITIES = ['FAIL', 'WARN', 'INFO', 'PASS'];
const VERDICT_LABELS = { PASS: 'Pass', PASS_WITH_WARNINGS: 'Pass with warnings', FAIL: 'Fail' };
const ICONS = { passed: '✓', failed: '✗', skipped: '–', active: '●', FAIL: '✗', WARN: '!', INFO: 'i', PASS: '✓' };
const STATE_LABELS = { active: 'running' };

const reducedMotion = () => Boolean(globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches);

let mounts = 0;

/**
 * Renders the scenario picker and the selected run into `el`.
 *
 * @param {HTMLElement} el      container; its contents are replaced
 * @param {object} [options]
 * @param {string} [options.baseUrl]       where manifest.json lives; defaults to this module's folder
 * @param {string} [options.run]           id of the run to show first; defaults to the first in the manifest
 * @param {number} [options.headingLevel]  level of the run title heading (default 2)
 * @param {boolean} [options.autoplay]     play each run as soon as it is picked (default false)
 * @returns {Promise<{ select(id: string): Promise<void>, play(): Promise<void>, showResult(): void }>}
 */
export async function mountReplay(el, options = {}) {
  const base = new URL(options.baseUrl || '.', options.baseUrl ? document.baseURI : import.meta.url);
  if (!base.pathname.endsWith('/')) base.pathname += '/';
  const level = Math.min(Math.max(options.headingLevel || 2, 1), 4);
  const hx = offset => `h${level + offset}`;
  const uid = `pw-replay-${++mounts}`;
  const cache = new Map();
  let current = 0;
  let player = null;
  const api = {
    select: async () => {},
    play: async () => player?.play(),
    showResult: () => player?.finish(),
  };

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
    return api;
  }
  const runs = manifest.runs || [];
  if (!runs.length) {
    status.textContent = 'This bundle has no recorded runs.';
    return api;
  }

  const load = run => {
    if (!cache.has(run.id)) {
      cache.set(run.id, getJson(new URL(run.file, base)).catch(e => { cache.delete(run.id); throw e; }));
    }
    return cache.get(run.id);
  };

  const inputs = new Map();
  const cards = runs.map((run, i) => {
    const id = `${uid}-${i}`;
    const input = h('input', { type: 'radio', name: `${uid}-scenario`, id, value: run.id, class: 'pw-radio' });
    input.addEventListener('change', () => input.checked && select(run.id));
    inputs.set(run.id, input);
    const tone = run.verdict === 'FAIL' ? 'FAIL' : 'PASS';
    const teaser = h('span', { class: 'pw-choice-teaser' }, teaserFor(run));
    const payer = h('span', { class: 'pw-choice-payer' }, run.payerName || run.payerId || '');
    // Without a recorded teaser or payer name, fill them in from the report once it loads.
    if (!run.teaser || !run.payerName) {
      load(run).then(report => {
        teaser.textContent = teaserFor(run, report);
        payer.textContent = run.payerName || report.payer?.displayName || run.payerId || '';
      }, () => {});
    }
    return h('label', { class: 'pw-choice', for: id },
      input,
      h('span', { class: 'pw-choice-head' },
        h('span', { class: 'pw-choice-title' }, run.title),
        run.verdict && h('span', { class: `pw-badge ${run.verdict}` }, VERDICT_LABELS[run.verdict] || run.verdict)),
      payer,
      h('span', { class: `pw-choice-line ${tone}` }, h('span', { class: 'pw-icon', 'aria-hidden': 'true' }, ICONS[tone]), teaser));
  });
  picker.replaceChildren(h('fieldset', {},
    h('legend', {}, 'Pick a scenario'),
    h('div', { class: 'pw-choices' }, cards)));

  async function select(id) {
    const run = runs.find(r => r.id === id);
    if (!run) return;
    inputs.get(run.id).checked = true;
    const token = ++current;
    player?.stop();
    player = null;
    status.textContent = `Loading ${run.title}…`;
    let report;
    try {
      report = await load(run);
    } catch (e) {
      if (token !== current) return;
      status.textContent = `Could not load ${run.title} (${e.message}).`;
      view.replaceChildren();
      return;
    }
    if (token !== current) return;
    player = createPlayer(run, report, hx, status);
    view.replaceChildren(...player.nodes);
    status.textContent = `Showing ${run.title}. Press Run to replay it.`;
    if (options.autoplay) player.play();
  }
  api.select = select;

  const first = runs.find(r => r.id === options.run) || runs[0];
  await select(first.id);
  return api;
}

/** One line on what breaks in a run: the manifest's teaser, else the first FAIL finding's title. */
export function teaserFor(run, report) {
  if (run.teaser) return run.teaser;
  if (!report) return run.description || '';
  const fail = (report.findings || []).find(f => f.severity === 'FAIL');
  if (fail) return fail.title;
  return report.verdict?.status === 'FAIL' ? 'Onboarding fails' : 'Healthy connection';
}

/** Playback duration of each step in ms; see TIMING. */
export function stepDurations(steps, timing = TIMING) {
  const raw = steps.map(s => Math.min(Math.max((s.elapsedMs || 0) * timing.scale, timing.minMs), timing.maxMs));
  const total = raw.reduce((a, b) => a + b, 0);
  const k = total > timing.totalMs ? timing.totalMs / total : 1;
  return raw.map(ms => Math.round(ms * k));
}

/** Index of the step where playback stops: the recorded brokeAt step, else the first failed one, else the last. */
export function stopIndex(report) {
  const steps = report.steps || [];
  const broke = report.verdict?.brokeAt;
  let i = broke ? steps.findIndex(s => s.status === 'failed' && s.title === broke) : -1;
  if (i < 0) i = steps.findIndex(s => s.status === 'failed');
  return i < 0 ? steps.length - 1 : i;
}

function createPlayer(run, report, hx, status) {
  const steps = report.steps || [];
  const last = stopIndex(report);
  const durations = stepDurations(steps.slice(0, last + 1));
  const total = durations.reduce((a, b) => a + b, 0);
  const latency = latencyInfo(report);
  const items = steps.map((s, i) => renderStep(s, hx, latency && latency.step === i ? latency : null));
  let timer = null;
  let index = -1;
  let done = null;

  const runButton = h('button', { type: 'button', class: 'pw-btn pw-primary' });
  const skipButton = h('button', { type: 'button', class: 'pw-btn', hidden: true }, 'Show result');
  const hint = h('span', { class: 'pw-hint' },
    `${steps.length} recorded step${steps.length === 1 ? '' : 's'}, replayed in about ${Math.max(1, Math.round(total / 1000))} s`);
  const result = h('div', { class: 'pw-result-slot' });
  const findings = h('section', { class: 'pw-section', hidden: true });
  const list = h('ol', { class: 'pw-steps' }, items);
  runButton.addEventListener('click', () => play());
  skipButton.addEventListener('click', () => {
    finish();
    runButton.focus?.();
  });
  setButton('Run', '▶');

  const meta = [
    report.payer && report.payer.displayName,
    report.environment,
    report.igVersion && `CRD IG ${report.igVersion}`,
    report.startedAt && `recorded ${report.startedAt.slice(0, 10)}`,
    report.workbenchVersion && `workbench ${report.workbenchVersion}`,
  ].filter(Boolean).join(' · ');

  function setButton(label, icon) {
    runButton.replaceChildren(`${label} `, h('span', { 'aria-hidden': 'true' }, icon));
  }

  function setState(i, state) {
    const item = items[i];
    item.className = `pw-step ${state}${i > last ? ' pw-after' : ''}`;
    const tag = item.tag;
    tag.className = `pw-status-tag ${state}`;
    tag.replaceChildren(h('span', { class: 'pw-icon', 'aria-hidden': 'true' }, ICONS[state] || ''), ` ${STATE_LABELS[state] || state}`);
    show(item, true);
  }

  function reset() {
    clearTimeout(timer);
    timer = null;
    index = -1;
    items.forEach(item => show(item, false));
    result.replaceChildren();
    findings.replaceChildren();
    show(findings, false);
  }

  function advance() {
    if (index >= 0) setState(index, steps[index].status || 'skipped');
    index++;
    if (index > last) {
      finish();
      return;
    }
    setState(index, 'active');
    items[index].style?.setProperty('--pw-dur', `${durations[index]}ms`);
    timer = setTimeout(advance, durations[index]);
  }

  function play() {
    reset();
    const finished = new Promise(resolve => { done = resolve; });
    if (reducedMotion()) {
      finish();
      return finished;
    }
    setButton('Run', '▶');
    runButton.setAttribute('disabled', '');
    show(skipButton, true);
    status.textContent = `Replaying ${run.title}…`;
    advance();
    return finished;
  }

  function finish() {
    clearTimeout(timer);
    timer = null;
    index = last;
    steps.forEach((s, i) => setState(i, s.status || 'skipped'));
    result.replaceChildren(renderResult(report, hx));
    findings.replaceChildren(h(hx(1), {}, 'Other findings'), ...renderFindings(report.findings || [], hx));
    show(findings, true);
    runButton.removeAttribute('disabled');
    setButton('Replay', '↻');
    show(skipButton, false);
    status.textContent = `${run.title}: ${resultLine(report)}`;
    done?.();
    done = null;
  }

  function stop() {
    clearTimeout(timer);
    timer = null;
    done?.();
    done = null;
  }

  const nodes = [
    h(hx(0), { class: 'pw-title' }, run.title),
    h('p', { class: 'pw-meta' }, meta),
    h('div', { class: 'pw-controls' }, runButton, skipButton, hint),
    result,
    h('section', { class: 'pw-section' },
      h(hx(1), {}, 'Step timeline'),
      list),
    findings,
  ];
  reset();
  return { nodes, play, finish, stop };
}

function resultLine(report) {
  const fail = (report.findings || []).find(f => f.severity === 'FAIL');
  if (fail) return `onboarding would fail. ${fail.title}.`;
  return 'onboarding would succeed.';
}

function renderStep(step, hx, latency) {
  const details = step.details || {};
  const exchanges = Array.isArray(details.exchanges) ? details.exchanges : [];
  const lines = exchanges.length ? [] : (step.exchanges || []);
  const extra = Object.fromEntries(Object.entries(details).filter(([k]) => k !== 'status' && k !== 'exchanges'));
  const hasExtra = Object.keys(extra).length > 0;
  const tag = h('span', { class: 'pw-status-tag' });
  const item = h('li', { class: 'pw-step' },
    h('div', { class: 'pw-step-head' },
      h(hx(2), {}, step.title || step.stepId),
      tag,
      step.status !== 'skipped' && h('span', { class: 'pw-latency' }, formatMs(step.elapsedMs || 0))),
    step.summary && h('p', { class: 'pw-summary' }, step.summary),
    latency && renderLatency(latency),
    (exchanges.length || lines.length || hasExtra) && h('details', { class: 'pw-step-details' },
      h('summary', {}, exchanges.length || lines.length ? 'Show request/response' : 'Show details'),
      h('div', {},
        exchanges.map(renderExchange),
        lines.map(line => h('p', { class: 'pw-mono' }, line)),
        hasExtra && [h('p', { class: 'pw-label' }, 'Step details'), h('pre', { tabindex: '0' }, JSON.stringify(extra, null, 2))],
        h('p', { class: 'pw-muted' }, 'Secrets, tokens and signatures were redacted before this run was recorded.'))));
  item.tag = tag;
  return item;
}

function renderExchange(x) {
  const status = x.status ? `HTTP ${x.status}` : 'no response';
  return h('div', { class: 'pw-exchange' },
    h('p', { class: 'pw-mono' }, `${x.method} ${x.url} → ${status} · ${formatMs(x.latencyMs || 0)}`),
    h('p', { class: 'pw-label' }, 'Request headers'), h('pre', { tabindex: '0' }, headers(x.requestHeaders)),
    x.requestBody && [h('p', { class: 'pw-label' }, 'Request body'), h('pre', { tabindex: '0' }, pretty(x.requestBody))],
    x.transportError && [h('p', { class: 'pw-label' }, 'Transport error'), h('pre', { tabindex: '0' }, x.transportError)],
    x.status ? [
      h('p', { class: 'pw-label' }, 'Response headers'), h('pre', { tabindex: '0' }, headers(x.responseHeaders)),
      h('p', { class: 'pw-label' }, 'Response body'),
      h('pre', { tabindex: '0' }, x.responseBody ? pretty(x.responseBody) : '(empty)'),
    ] : null);
}

/**
 * For a run with a WARN or FAIL perf.latency finding: which step made the slow call,
 * its real recorded ms and the budgets it was judged against.
 */
export function latencyInfo(report) {
  const findings = (report.findings || []).filter(f => f.checkId === 'perf.latency');
  const slow = findings.find(f => f.severity === 'FAIL') || findings.find(f => f.severity === 'WARN');
  if (!slow) return null;
  const steps = report.steps || [];
  const text = findings.map(f => f.explanation || '').join(' ');
  const num = re => { const m = re.exec(text); return m ? Math.round(parseFloat(m[1]) * 1000) : null; };
  const failMs = num(/longer than (\d+(?:\.\d+)?) s\b/) || LATENCY_BUDGET.failMs;
  const warnMs = num(/than the (\d+(?:\.\d+)?) s budget/) || Math.min(LATENCY_BUDGET.warnMs, failMs);
  // The evidence starts with the slow call: "POST <url> -> HTTP 200 in 11005 ms".
  const [, method, url, took] = /^(\S+) (\S+) -> .*?\bin (\d+) ms\b/m.exec(slow.evidence || '') || [];
  const calls = steps.map(s => s.details?.exchanges || []);
  let step = calls.findIndex(c => c.some(x => x.method === method && x.url === url));
  if (step < 0) step = steps.findIndex(s => s.stepId === 'hook-request');
  if (step < 0) return null;
  const ms = Number(took) || Math.max(steps[step].elapsedMs || 0, ...calls[step].map(x => x.latencyMs || 0));
  return { step, ms, warnMs, failMs, severity: slow.severity };
}

function renderLatency({ ms, warnMs, failMs, severity }) {
  // The track runs past the fail budget so an overshoot is visible.
  const scale = Math.max(failMs * 1.25, ms * 1.08);
  const pct = v => `${(100 * v / scale).toFixed(1)}%`;
  const fill = h('span', { class: `pw-bar-fill ${severity}` });
  fill.style?.setProperty('--pw-fill', pct(ms));
  const mark = (v, cls) => {
    const m = h('span', { class: `pw-bar-mark ${cls}` });
    m.style?.setProperty('left', pct(v));
    return m;
  };
  const over = ms > failMs ? `over the ${seconds(failMs)} fail budget` : `over the ${seconds(warnMs)} warn budget`;
  return h('div', { class: 'pw-bar' },
    h('span', { class: 'pw-bar-track', 'aria-hidden': 'true' }, fill, mark(warnMs, 'warn'), mark(failMs, 'fail')),
    h('p', { class: `pw-bar-label ${severity}` },
      h('span', { class: 'pw-icon', 'aria-hidden': 'true' }, ICONS[severity]),
      ` ${ms.toLocaleString('en-US')} ms recorded, ${over} (warn ${seconds(warnMs)}, fail ${seconds(failMs)})`));
}

function renderResult(report, hx) {
  const findings = report.findings || [];
  const verdict = report.verdict || {};
  const fails = findings.filter(f => f.severity === 'FAIL');
  if (fails.length) {
    const [first, ...more] = fails;
    return h('section', { class: 'pw-result FAIL' },
      h('p', { class: 'pw-result-kicker' }, h('span', { class: 'pw-icon', 'aria-hidden': 'true' }, ICONS.FAIL),
        verdict.brokeAt ? ` Onboarding would fail at ${verdict.brokeAt}` : ' Onboarding would fail'),
      h(hx(1), { class: 'pw-result-title' }, first.title),
      first.explanation && h('p', {}, first.explanation),
      first.suggestedFix && h('p', { class: 'pw-fix' }, h('strong', {}, 'Fix: '), first.suggestedFix),
      h('code', {}, first.checkId),
      first.evidence && evidence(first),
      more.length > 0 && h('details', { class: 'pw-more' },
        h('summary', {}, `+${more.length} more failing check${more.length === 1 ? '' : 's'}`),
        h('div', {}, more.map(f => renderFinding(f, hx)))));
  }
  const count = sev => findings.filter(f => f.severity === sev).length;
  const verified = (report.steps || []).filter(s => s.status === 'passed').map(s => s.title || s.stepId);
  const warns = count('WARN');
  return h('section', { class: `pw-result ${verdict.status || 'PASS'}` },
    h('p', { class: 'pw-result-kicker' }, h('span', { class: 'pw-icon', 'aria-hidden': 'true' }, ICONS.PASS),
      ` ${VERDICT_LABELS[verdict.status] || 'Pass'}`),
    h(hx(1), { class: 'pw-result-title' }, 'Onboarding would succeed'),
    h('p', {}, `Verified against ${report.payer?.displayName || 'the synthetic payer'}: ${verified.join(', ')}. `,
      `${count('PASS')} check${count('PASS') === 1 ? '' : 's'} passed`,
      warns ? `, with ${warns} warning${warns === 1 ? '' : 's'} below.` : '.'));
}

function renderFindings(findings, hx) {
  const others = findings.filter(f => f.severity === 'WARN' || f.severity === 'INFO');
  const passed = findings.filter(f => f.severity === 'PASS');
  const out = SEVERITIES.slice(1, 3).flatMap(sev => others.filter(f => f.severity === sev).map(f => renderFinding(f, hx)));
  if (passed.length) {
    // Passing checks collapse to one line so the answer stays in view.
    out.push(h('details', { class: 'pw-passed' },
      h('summary', {}, h('span', { class: 'pw-icon', 'aria-hidden': 'true' }, ICONS.PASS),
        ` ${passed.length} check${passed.length === 1 ? '' : 's'} passed`),
      h('ul', {}, passed.map(f => h('li', {},
        h('span', {}, f.title), ' ', h('code', {}, f.checkId),
        f.explanation && h('span', { class: 'pw-muted' }, ` ${f.explanation}`))))));
  }
  return out.length ? out : [h('p', { class: 'pw-muted' }, 'No findings.')];
}

/** A compact finding: one line with severity, title and check id; the rest behind a disclosure. */
function renderFinding(f, hx) {
  const more = f.explanation || f.suggestedFix || f.evidence;
  return h('article', { class: `pw-finding ${f.severity}` },
    h('div', { class: 'pw-finding-head' },
      h('span', { class: `pw-badge ${f.severity}` }, h('span', { 'aria-hidden': 'true' }, `${ICONS[f.severity]} `), f.severity),
      h(hx(2), {}, f.title),
      h('code', {}, f.checkId)),
    more && h('details', {},
      h('summary', {}, 'Why it matters'),
      h('div', {},
        f.explanation && h('p', {}, f.explanation),
        f.suggestedFix && h('p', { class: 'pw-fix' }, h('strong', {}, 'Fix: '), f.suggestedFix),
        f.evidence && [h('p', { class: 'pw-label' }, 'Evidence'), h('pre', { tabindex: '0' }, f.evidence)])));
}

function evidence(f) {
  return h('details', {}, h('summary', {}, 'Evidence'), h('div', {}, h('pre', { tabindex: '0' }, f.evidence)));
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

function show(el, on) {
  if (on) el.removeAttribute('hidden');
  else el.setAttribute('hidden', '');
}

function seconds(ms) {
  return `${+(ms / 1000).toFixed(1)} s`;
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
