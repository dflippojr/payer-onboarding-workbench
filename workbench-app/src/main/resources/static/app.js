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
    'discovery-500': ['Discovery is down', 'GET /cds-services returns 500.'],
    'prefetch-missing-400': ['Strict about prefetch', 'Rejects requests that leave out prefetch. Pick the "missing prefetch" sample to see it.'],
    'untrusted-certificate': ['Untrusted certificate', 'Presents a certificate issued by an untrusted test CA.'],
    'expired-certificate': ['Expired certificate', 'Presents a trusted certificate that expired yesterday.'],
    'hostname-mismatch': ['Certificate hostname mismatch', 'Presents a trusted certificate for a different payer host.'],
  };
  const SEVERITIES = ['FAIL', 'WARN', 'INFO', 'PASS'];

  const $ = id => document.getElementById(id);
  const form = $('run-form');
  let payers = [];
  let samples = [];
  let lastRunId = null;
  let customEnabled = false;
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

  async function api(path, options) {
    const res = await fetch(path, options);
    const body = await res.json().catch(() => null);
    if (!res.ok) throw new Error((body && (body.detail || body.message)) || `HTTP ${res.status}`);
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
    $('customTokenEndpointField').hidden = type !== 'OAUTH2_CLIENT_CREDENTIALS';
    $('customKeyIdField').hidden = type !== 'CDS_HOOKS_JWT';
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
    } catch (e) {
      $('run-status').textContent = `Run failed: ${e.message}`;
    } finally {
      button.disabled = false;
    }
  }

  function renderRun(result, payer) {
    const failed = result.steps.find(s => s.details.status === 'failed' && s.stepId !== 'diagnostics');
    $('run-meta').textContent = `${payer.displayName} · ${result.environment} · run ${result.runId}` +
      (failed ? ` · broke at: ${STEP_TITLES[failed.stepId] || failed.stepId}` : ' · every step passed');
    $('steps').replaceChildren(...result.steps.map(renderStep));
    renderFindings(result.findings);
    lastRunId = result.runId;
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
    const status = step.details.status || (step.ok ? 'passed' : 'failed');
    const extra = Object.fromEntries(Object.entries(step.details).filter(([k]) => k !== 'status' && k !== 'exchanges'));
    return h('li', { class: `step ${status}` },
      h('div', { class: 'step-head' },
        h('h3', {}, STEP_TITLES[step.stepId] || step.stepId),
        h('span', { class: `status ${status}` }, status),
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
      const cards = group.map(f => h('article', { class: `finding ${f.severity}` },
        h('h4', {}, f.title),
        h('code', {}, f.checkId),
        f.explanation && h('p', {}, f.explanation),
        f.evidence && h('details', {}, h('summary', {}, 'Evidence'), h('div', {}, h('pre', {}, f.evidence))),
        f.suggestedFix && h('p', { class: 'fix' }, h('strong', {}, 'Fix: '), f.suggestedFix)));
      const heading = h('h3', {}, h('span', { class: `sev ${sev}` }, sev), `${group.length} finding${group.length === 1 ? '' : 's'}`);
      // Passing checks are collapsed so failures stay in view.
      return sev === 'PASS'
        ? h('section', { class: 'sev-group' }, h('details', {}, h('summary', {}, heading), h('div', {}, cards)))
        : h('section', { class: 'sev-group' }, heading, cards);
    }).filter(Boolean));
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

  init();
})();
