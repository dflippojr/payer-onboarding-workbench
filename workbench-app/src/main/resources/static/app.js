// Payer onboarding workbench UI. Plain DOM, no build step. All server text goes in via textContent.
(() => {
  'use strict';

  const STEP_TITLES = {
    'resolve-connection': 'Resolve connection',
    'discovery': 'Discovery',
    'authenticate': 'Authenticate',
    'hook-request': 'Send sample hook request',
    'parse-response': 'Parse response',
    'diagnostics': 'Run diagnostics',
  };
  const FAULTS = {
    'slow-response': ['Payer is slow', 'Every response is held past the latency budget (about 11 s by default).'],
    'rate-limited-429': ['Payer rate limit', 'Hook calls get 429 with Retry-After: 30; back off before retrying.'],
    'expired-token-401': ['Token rejected as expired', 'Hook calls get 401 invalid_token, "expired".'],
    'wrong-audience-reject': ['Payer expects another audience', 'The payer checks tokens against a different aud.'],
    'malformed-card': ['Malformed cards', 'Cards come back without summary and indicator.'],
    'coverage-info-incomplete': ['Incomplete coverage information', 'Order-sign responses omit the coverage assertion ID and use an invalid covered value.'],
    'discovery-500': ['Discovery is down', 'GET /cds-services returns 500.'],
    'prefetch-missing-400': ['Strict about prefetch', 'Rejects requests that leave out prefetch. Pick the "missing prefetch" sample to see it.'],
    'untrusted-certificate': ['Untrusted certificate', 'Presents a certificate issued by an untrusted test CA.'],
    'expired-certificate': ['Expired certificate', 'Presents a trusted certificate that expired yesterday.'],
    'hostname-mismatch': ['Certificate hostname mismatch', 'Presents a trusted certificate for a different payer host.'],
  };
  const SEVERITIES = ['FAIL', 'WARN', 'INFO', 'PASS'];
  const VERDICTS = ['FAIL', 'PASS_WITH_WARNINGS', 'PASS'];

  const $ = id => document.getElementById(id);
  const form = $('run-form');
  let payers = [];
  let samples = [];
  let lastRunId = null;
  let customEnabled = false;
  let retrieval = 0;
  let comparing = 0;
  let history = [];
  let currentRun = null;
  const CUSTOM = '__custom__';

  /** Builds an element; children may be strings, nodes, arrays or null. */
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'class') el.className = v;
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

  const SVG = 'http://www.w3.org/2000/svg';
  const ICONS = {
    pass: [['circle', { cx: 10, cy: 10, r: 8.5 }], ['path', { d: 'M6.5 10.2l2.3 2.3 4.7-4.9' }]],
    fail: [['circle', { cx: 10, cy: 10, r: 8.5 }], ['path', { d: 'M7 7l6 6M13 7l-6 6' }]],
    warn: [['path', { d: 'M10 2.5l8 14.5H2z' }], ['path', { d: 'M10 8v4M10 14.5v.5' }]],
    info: [['circle', { cx: 10, cy: 10, r: 8.5 }], ['path', { d: 'M10 9v5M10 6v.5' }]],
    skipped: [['circle', { cx: 10, cy: 10, r: 8.5, 'stroke-dasharray': '3 3' }], ['path', { d: 'M6.5 10h7' }]],
    pending: [['circle', { cx: 10, cy: 10, r: 8.5, 'stroke-dasharray': '2.5 2.5' }]],
  };
  /** Chip kind and word for each step status and finding severity. */
  const STATUS = {
    passed: ['pass', 'Passed'], failed: ['fail', 'Failed'], skipped: ['skipped', 'Skipped'], pending: ['pending', 'Pending'],
    PASS: ['pass', 'Pass'], FAIL: ['fail', 'Fail'], WARN: ['warn', 'Warn'], INFO: ['info', 'Info'],
  };

  /** A decorative inline SVG status icon (pass, fail, warn, info, skipped or pending); the word beside it carries the meaning. */
  function statusIcon(kind, size = 14) {
    const svg = document.createElementNS(SVG, 'svg');
    const attrs = { class: `icon ${kind}`, width: size, height: size, viewBox: '0 0 20 20', fill: 'none',
      stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false' };
    for (const [k, v] of Object.entries(attrs)) svg.setAttribute(k, v);
    for (const [tag, shape] of ICONS[kind] || ICONS.info) {
      const el = document.createElementNS(SVG, tag);
      for (const [k, v] of Object.entries(shape)) el.setAttribute(k, v);
      svg.append(el);
    }
    return svg;
  }

  /** A status chip: icon plus word, so colour is never the only signal. */
  function statusChip(status, word) {
    const [kind, label] = STATUS[status] || ['info', status];
    return h('span', { class: `chip ${kind}` }, statusIcon(kind, 12), word || label);
  }

  async function api(path, options) {
    const res = await fetch(path, options);
    const body = await res.json().catch(() => null);
    if (!res.ok) {
      const error = new Error((body && (body.detail || body.message)) || `HTTP ${res.status}`);
      error.status = res.status;
      throw error;
    }
    return body;
  }

  // ---- setup ----

  async function init() {
    try {
      [payers, samples] = await Promise.all([api('api/payers'), api('api/samples')]);
    } catch (e) {
      $('payers').replaceChildren(h('p', { class: 'muted' }, `Could not load payers: ${e.message}`));
      return;
    }
    customEnabled = await api('api/features').then(f => !!f.customEndpoints, () => false);
    renderPayers();
    renderSamples();
    renderFaults(payers[0] ? payers[0].faults : Object.keys(FAULTS));
    updateConnectionHints();
    form.addEventListener('submit', run);
    $('reset-button').addEventListener('click', reset);
    $('sample').addEventListener('change', updateSampleNote);
    $('customAuthType').addEventListener('change', updateCustomFields);
    $('report-format').addEventListener('change', updateReportLink);
    $('recent-runs').addEventListener('change', reopenRun);
    $('compare-runs').addEventListener('change', compareRun);
    await refreshHistory();
  }

  async function refreshHistory() {
    try {
      history = await api('api/runs');
      const selector = $('recent-runs');
      selector.replaceChildren(h('option', { value: '' }, history.length ? 'Choose a run' : 'No recent runs yet'),
        ...history.map(r => h('option', { value: r.runId }, historyLabel(r))));
      selector.value = history.some(r => r.runId === lastRunId) ? lastRunId : '';
      $('history-status').textContent = history.length ? '' : 'Run onboarding to build history. Restarting the server clears it.';
    } catch (e) {
      history = [];
      $('recent-runs').replaceChildren(h('option', { value: '' }, 'History unavailable'));
      $('history-status').textContent = `Could not load recent runs: ${e.message}. You can still run onboarding.`;
    }
    renderCompareOptions();
  }

  function historyLabel(r) {
    return `${r.payerId} | ${r.environment} | ${r.startedAt || 'No steps'} | ${r.verdict}`;
  }

  /** Offers every retained run except the one on screen; enabled only while a run is shown. */
  function renderCompareOptions() {
    const selector = $('compare-runs');
    const others = currentRun ? history.filter(r => r.runId !== currentRun.runId) : [];
    let prompt = 'Show a run first';
    if (currentRun) prompt = others.length ? 'Choose a run to compare' : 'No other runs to compare';
    const keep = selector.value;
    selector.replaceChildren(h('option', { value: '' }, prompt), ...others.map(r => h('option', { value: r.runId }, historyLabel(r))));
    selector.value = others.some(r => r.runId === keep) ? keep : '';
    selector.disabled = !currentRun || $('run-button').disabled;
  }

  async function compareRun() {
    const id = $('compare-runs').value;
    const ticket = ++comparing;
    if (!id || !currentRun) {
      clearComparison();
      return;
    }
    const shown = currentRun;
    $('history-status').textContent = 'Loading run to compare...';
    try {
      const baseline = await api(`api/runs/${encodeURIComponent(id)}`);
      if (ticket !== comparing) return;
      renderComparison(baseline, compareRuns(baseline, shown));
      $('history-status').textContent = 'Comparison shown.';
    } catch (e) {
      if (ticket !== comparing) return;
      if (e.status === 404) {
        hideComparison();
        await refreshHistory();
        if (ticket !== comparing) return;
        $('history-status').textContent = 'That run is no longer available. It may have been evicted or the server restarted.';
      } else {
        $('history-status').textContent = `Could not load run to compare: ${e.message}`;
      }
    }
  }

  /** Hides the comparison and invalidates any comparison fetch still in flight. */
  function clearComparison() {
    ++comparing;
    hideComparison();
  }

  function hideComparison() {
    $('compare-runs').value = '';
    $('comparison').hidden = true;
    $('comparison-body').replaceChildren();
  }

  async function reopenRun() {
    const id = $('recent-runs').value;
    const ticket = ++retrieval;
    if (!id) return;
    $('history-status').textContent = 'Loading run...';
    try {
      const result = await api(`api/runs/${encodeURIComponent(id)}`);
      if (ticket !== retrieval) return;
      const payer = payers.find(p => p.payerId === result.payerId) || { displayName: result.payerId };
      renderRun(result, payer);
      $('history-status').textContent = 'Run reopened.';
    } catch (e) {
      if (ticket !== retrieval) return;
      if (e.status === 404) {
        lastRunId = null;
        currentRun = null;
        clearComparison();
        $('report-actions').hidden = true;
        $('report-link').removeAttribute('href');
        $('steps').replaceChildren();
        $('findings').replaceChildren();
        $('run-meta').textContent = 'Choose another recent run or run onboarding.';
        await refreshHistory();
        if (ticket !== retrieval) return;
        $('history-status').textContent = 'This run is no longer available. It may have been evicted or the server restarted.';
      } else {
        $('history-status').textContent = `Could not reopen run: ${e.message}`;
      }
    }
  }

  function renderPayers() {
    $('payers').replaceChildren(...payers.map((p, i) => {
      const conn = p.connections[0] || {};
      return h('label', { class: 'pick' },
        h('input', { type: 'radio', name: 'payerId', value: p.payerId, checked: i === 0, onchange: updateConnectionHints }),
        h('strong', {}, p.displayName),
        h('span', {}, `CRD ${p.advertisedIgVersion} · ${authLabel(conn.authType)}`),
        h('span', {}, p.payerId));
    }).concat(customEnabled ? [h('label', { class: 'pick' },
      h('input', { type: 'radio', name: 'payerId', value: CUSTOM, onchange: updateConnectionHints }),
      h('strong', {}, 'Your own endpoint'),
      h('span', {}, 'A payer you supply, e.g. a local reference server'),
      h('span', {}, 'custom-endpoint'))] : []));
  }

  function authLabel(type) {
    return ({ OAUTH2_CLIENT_CREDENTIALS: 'OAuth2 client credentials', OAUTH2_PRIVATE_KEY_JWT: 'SMART Backend Services (private_key_jwt)', CDS_HOOKS_JWT: 'CDS Hooks client JWT' })[type] || type || 'no auth';
  }

  function renderSamples() {
    $('sample').replaceChildren(...samples.map(s => h('option', { value: s.id }, `${s.title} (${s.hook})`)));
    updateSampleNote();
  }

  function updateSampleNote() {
    const s = samples.find(x => x.id === $('sample').value);
    $('sample-note').textContent = s ? s.demonstrates : '';
  }

  function renderFaults(ids) {
    $('faults').replaceChildren(...ids.map(id => {
      const [label, help] = FAULTS[id] || [id, ''];
      return h('label', { class: 'check' },
        h('input', { type: 'checkbox', name: 'fault', value: id }),
        h('span', {}, label, h('code', {}, id), h('span', { class: 'muted small' }, help)));
    }));
  }

  function selectedPayer() {
    const checked = form.querySelector('input[name="payerId"]:checked');
    return payers.find(p => checked && p.payerId === checked.value);
  }

  function customSelected() {
    const checked = form.querySelector('input[name="payerId"]:checked');
    return !!checked && checked.value === CUSTOM;
  }

  function updateCustomFields() {
    const type = $('customAuthType').value;
    $('customTokenEndpointField').hidden = type !== 'OAUTH2_CLIENT_CREDENTIALS' && type !== 'OAUTH2_PRIVATE_KEY_JWT';
    $('customKeyIdField').hidden = type !== 'CDS_HOOKS_JWT' && type !== 'OAUTH2_PRIVATE_KEY_JWT';
    $('customCredentialField').hidden = type === 'NONE';
    $('customClientId').closest('label').hidden = type === 'NONE';
  }

  function updateConnectionHints() {
    $('custom-endpoint').hidden = !customSelected();
    updateCustomFields();
    const p = selectedPayer();
    if (!p) return;
    const conn = p.connections.find(c => c.environment === 'SANDBOX') || p.connections[0] || {};
    $('baseUrl-hint').textContent = `stored: ${conn.baseUrl || '—'}`;
    $('igVersion').placeholder = conn.igVersion || '';
    $('igVersion-hint').textContent = `stored: ${conn.igVersion || '—'} (payer advertises ${p.advertisedIgVersion})`;
    $('clientId').placeholder = conn.clientId || '';
    $('clientId-hint').textContent = `stored: ${conn.clientId || '—'}`;

  }

  function reset() {
    form.querySelectorAll('input[name="fault"]').forEach(c => { c.checked = false; });
    ['baseUrlSuffix', 'igVersion', 'clientId', 'customCredential'].forEach(id => { $(id).value = ''; });
    $('run-status').textContent = 'Faults and settings reset.';
  }

  // ---- run ----

  async function run(event) {
    event.preventDefault();
    const custom = customSelected();
    const p = custom ? { payerId: null, displayName: 'Custom endpoint' } : selectedPayer();
    if (!p) return;
    const value = id => $(id).value.trim() || null;
    const request = {
      payerId: p.payerId,
      environment: $('environment').value,
      sampleId: $('sample').value,
      faults: [...form.querySelectorAll('input[name="fault"]:checked')].map(c => c.value),
      connection: {
        baseUrlSuffix: value('baseUrlSuffix'),
        igVersion: value('igVersion'),
        clientId: value('clientId'),
      },
    };
    if (custom) {
      request.faults = [];
      request.customEndpoint = {
        baseUrl: value('customBaseUrl'),
        authType: $('customAuthType').value,
        clientId: value('customClientId'),
        tokenEndpoint: value('customTokenEndpoint'),
        keyId: value('customKeyId'),
        credential: $('customCredential').value.trim() || null,
      };
    }
    const button = $('run-button');
    button.disabled = true;
    ++retrieval;
    clearComparison();
    $('recent-runs').disabled = true;
    $('compare-runs').disabled = true;
    $('run-status').textContent = request.faults.includes('slow-response')
      ? 'Running… the slow-response fault takes several seconds.'
      : 'Running…';
    try {
      const result = await api('api/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      });
      renderRun(result, p);
      const fails = result.findings.filter(f => f.severity === 'FAIL').length;
      $('run-status').textContent = fails ? `Done: ${fails} failing check${fails === 1 ? '' : 's'}.` : 'Done: no failures.';
      $('steps-heading').focus();
      await refreshHistory();
    } catch (e) {
      $('run-status').textContent = `Run failed: ${e.message}`;
    } finally {
      button.disabled = false;
      $('recent-runs').disabled = false;
      renderCompareOptions();
    }
  }

  function renderRun(result, payer) {
    const failed = brokeAt(result);
    $('run-meta').textContent = `${payer.displayName} · ${result.environment} · run ${result.runId}` +
      (failed ? ` · broke at: ${stepTitle(failed)}` : ' · every step passed');
    $('steps').replaceChildren(...result.steps.map(renderStep));
    renderFindings(result.findings);
    lastRunId = result.runId;
    currentRun = result;
    clearComparison();
    renderCompareOptions();
    updateReportLink();
    $('report-actions').hidden = false;
  }

  function updateReportLink() {
    if (!lastRunId) return;
    const format = $('report-format').value;
    const link = $('report-link');
    link.href = `api/runs/${encodeURIComponent(lastRunId)}/report?format=${format}`;
    link.setAttribute('download', `onboarding-report-${lastRunId}.${format}`);
  }

  function renderStep(step) {
    const status = stepStatus(step);
    const extra = Object.fromEntries(Object.entries(step.details).filter(([k]) => k !== 'status' && k !== 'exchanges'));
    return h('li', { class: `step ${status}` },
      h('div', { class: 'step-head' },
        h('h3', {}, STEP_TITLES[step.stepId] || step.stepId),
        statusChip(status),
        status !== 'skipped' && h('span', { class: 'latency' }, formatMs(durationMs(step.elapsed)))),
      h('p', {}, step.summary),
      (step.details.exchanges || []).map(renderExchange),
      Object.keys(extra).length > 0 && h('details', {},
        h('summary', {}, 'Step details'),
        h('div', {}, h('pre', {}, JSON.stringify(extra, null, 2)))));
  }

  function renderExchange(x) {
    const status = x.status ? `HTTP ${x.status}` : 'no response';
    return h('details', {},
      h('summary', {}, `${x.method} ${x.url} → ${status} · ${formatMs(x.latencyMs)}`),
      h('div', {},
        h('p', { class: 'label' }, 'Request headers'), h('pre', {}, headers(x.requestHeaders)),
        x.requestBody && [h('p', { class: 'label' }, 'Request body'), h('pre', {}, pretty(x.requestBody))],
        x.transportError && [h('p', { class: 'label' }, 'Transport error'), h('pre', {}, x.transportError)],
        x.status ? [
          h('p', { class: 'label' }, 'Response headers'), h('pre', {}, headers(x.responseHeaders)),
          h('p', { class: 'label' }, 'Response body'), h('pre', {}, x.responseBody ? pretty(x.responseBody) : '(empty)'),
        ] : null,
        h('p', { class: 'muted small' }, 'Secrets, tokens and signatures are redacted before they reach this page.')));
  }

  function renderFindings(findings) {
    if (!findings.length) {
      $('findings').replaceChildren(h('p', { class: 'muted small' }, 'No findings.'));
      return;
    }
    $('findings').replaceChildren(...SEVERITIES.map(sev => {
      const group = findings.filter(f => f.severity === sev);
      if (!group.length) return null;
      const cards = group.map(f => h('article', { class: `finding card ${f.severity}` },
        h('div', { class: 'finding-head' }, statusChip(f.severity), h('h4', {}, f.title)),
        h('code', {}, f.checkId),
        f.explanation && h('p', {}, f.explanation),
        f.evidence && h('details', {}, h('summary', {}, 'Evidence'), h('div', {}, h('pre', {}, f.evidence))),
        f.suggestedFix && h('p', { class: 'fix' }, h('strong', {}, 'Fix: '), f.suggestedFix)));
      const heading = h('h3', {}, statusChip(sev), `${group.length} finding${group.length === 1 ? '' : 's'}`);
      // Passing checks are collapsed so failures stay in view.
      return sev === 'PASS'
        ? h('section', { class: 'sev-group' }, h('details', {}, h('summary', {}, heading), h('div', {}, cards)))
        : h('section', { class: 'sev-group' }, heading, cards);
    }).filter(Boolean));
  }

  // ---- comparison ----

  function stepStatus(step) {
    return step.details.status || (step.ok ? 'passed' : 'failed');
  }

  function stepTitle(stepId) {
    return STEP_TITLES[stepId] || stepId;
  }

  /** The first failed step other than diagnostics, as in RunVerdict. */
  function brokeAt(run) {
    const failed = run.steps.find(s => s.stepId !== 'diagnostics' && stepStatus(s) === 'failed');
    return failed ? failed.stepId : null;
  }

  /** Same rule as RunVerdict.status: a failing check or a broken step fails the run. */
  function verdictOf(run) {
    if (brokeAt(run) || run.findings.some(f => f.severity === 'FAIL')) return 'FAIL';
    return run.findings.some(f => f.severity === 'WARN') ? 'PASS_WITH_WARNINGS' : 'PASS';
  }

  /** Severity rank, lower is worse. */
  function rank(severity) {
    return SEVERITIES.indexOf(severity);
  }

  /** The most severe finding per checkId. */
  function worstByCheck(findings) {
    const worst = new Map();
    for (const f of findings) {
      const seen = worst.get(f.checkId);
      if (!seen || rank(f.severity) < rank(seen.severity)) worst.set(f.checkId, f);
    }
    return worst;
  }

  /** Lower ranks are worse. */
  function direction(before, after) {
    if (after < before) return 'worse';
    return after > before ? 'better' : 'unchanged';
  }

  /**
   * Pure comparison of two runs as returned by GET /api/runs/{id}: what changed from before to after.
   * A severity or step status is null when that run did not report it; checks reported by only one run
   * are listed in oneSided rather than ranked as better or worse.
   */
  function compareRuns(before, after) {
    const was = worstByCheck(before.findings);
    const now = worstByCheck(after.findings);
    const checks = [...new Set([...was.keys(), ...now.keys()])].map(checkId => {
      const b = was.get(checkId);
      const a = now.get(checkId);
      return { checkId, title: (a || b).title, before: b ? b.severity : null, after: a ? a.severity : null };
    }).sort((x, y) => rank(x.after || x.before) - rank(y.after || y.before)
      || rank(x.before || x.after) - rank(y.before || y.after) || x.checkId.localeCompare(y.checkId));
    const both = checks.filter(c => c.before && c.after);
    const statuses = run => new Map(run.steps.map(s => [s.stepId, stepStatus(s)]));
    const stepsBefore = statuses(before);
    const stepsAfter = statuses(after);
    const steps = [...new Set([...stepsBefore.keys(), ...stepsAfter.keys()])]
      .map(stepId => ({ stepId, before: stepsBefore.get(stepId) || null, after: stepsAfter.get(stepId) || null }))
      .filter(s => s.before !== s.after);
    const verdictBefore = verdictOf(before);
    const verdictAfter = verdictOf(after);
    return {
      before: before.runId,
      after: after.runId,
      verdict: { before: verdictBefore, after: verdictAfter,
        change: direction(VERDICTS.indexOf(verdictBefore), VERDICTS.indexOf(verdictAfter)) },
      brokeAt: { before: brokeAt(before), after: brokeAt(after) },
      steps,
      worse: both.filter(c => rank(c.after) < rank(c.before)),
      better: both.filter(c => rank(c.after) > rank(c.before)),
      unchanged: both.filter(c => rank(c.after) === rank(c.before)),
      oneSided: checks.filter(c => !c.before || !c.after),
    };
  }

  function renderComparison(baseline, diff) {
    const arrow = (b, a) => h('span', { class: 'transition' }, `${b} → ${a}`);
    const brokeLabel = id => (id ? stepTitle(id) : 'every step passed');
    const run = id => `run ${String(id).slice(0, 8)}`;
    const oneSided = c => h('span', { class: 'transition' },
      c.after ? `only in ${run(diff.after)}: ${c.after}` : `only in ${run(diff.before)}: ${c.before}`);
    const group = (title, items, change = c => arrow(c.before, c.after)) => [
      h('h4', {}, `${title} (${items.length})`),
      items.length
        ? h('ul', { class: 'changes' }, items.map(c => h('li', {},
          h('code', {}, c.checkId), ' ', c.title, ' ', change(c))))
        : h('p', { class: 'muted small' }, 'None.'),
    ];
    const { before: brokeBefore, after: brokeAfter } = diff.brokeAt;
    $('comparison-heading').textContent = `Changes since run ${String(baseline.runId).slice(0, 8)}`;
    $('comparison-body').replaceChildren(
      h('dl', { class: 'compare-summary' },
        h('dt', {}, 'Verdict'),
        h('dd', {}, arrow(diff.verdict.before, diff.verdict.after), ' ', h('strong', {}, diff.verdict.change)),
        h('dt', {}, 'Broke at'),
        h('dd', {}, brokeBefore === brokeAfter
          ? `${brokeLabel(brokeAfter)} (unchanged)`
          : arrow(brokeLabel(brokeBefore), brokeLabel(brokeAfter)))),
      h('h4', {}, 'Steps that changed'),
      diff.steps.length
        ? h('ul', { class: 'changes' }, diff.steps.map(s =>
          h('li', {}, `${stepTitle(s.stepId)}: `, arrow(s.before || 'not run', s.after || 'not run'))))
        : h('p', { class: 'muted small' }, 'No step changed status.'),
      ...group('Newly failing or worse', diff.worse),
      ...group('Fixed or better', diff.better),
      ...group('Only in one run', diff.oneSided, oneSided),
      h('p', { class: 'muted small' }, `Unchanged: ${diff.unchanged.length} check${diff.unchanged.length === 1 ? '' : 's'}.`));
    $('comparison').hidden = false;
  }

  // ---- formatting ----

  /** Jackson may send a Duration as seconds (number) or ISO-8601 ("PT0.012S"). */
  function durationMs(d) {
    if (typeof d === 'number') return d * 1000;
    const m = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?$/.exec(d || '');
    return m ? ((+m[1] || 0) * 3600 + (+m[2] || 0) * 60 + (+m[3] || 0)) * 1000 : 0;
  }

  function formatMs(ms) {
    return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`;
  }

  function headers(map) {
    return Object.entries(map || {}).map(([k, vs]) => `${k}: ${[].concat(vs).join(', ')}`).join('\n') || '(none)';
  }

  function pretty(text) {
    try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
  }

  // Exposed so the Node tests can exercise the comparison without a browser.
  globalThis.PayerWorkbench = Object.freeze({ compareRuns });
  init();
})();
