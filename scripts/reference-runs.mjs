#!/usr/bin/env node
// The outside judge: runs the workbench against the HL7 Da Vinci CRD reference server,
// a CDS Hooks / CRD implementation this project didn't write, and checks the workbench's
// verdicts against what the specs say that server's answers mean.
//
//   bash scripts/crd-reference-server.sh start     # Docker; pinned in crd-reference-server.env
//   node --test scripts/reference-runs.mjs         # builds the jar unless REFERENCE_SKIP_BUILD=1
//   bash scripts/crd-reference-server.sh stop
//
// CRD_RI_BASE_URL overrides http://127.0.0.1:18090/r4. Each run's JSON report is written
// to .crd-ri/reports/. Every sample in samples/index.json gets a test; none is skipped.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createWorkbench, root } from './workbench-lifecycle.mjs';

const serverBase = (process.env.CRD_RI_BASE_URL ?? 'http://127.0.0.1:18090/r4').replace(/\/$/, '');
const samplesDir = join(root, 'samples', 'src', 'main', 'resources', 'samples');
const sampleIds = JSON.parse(readFileSync(join(samplesDir, 'index.json'), 'utf8'));
const out = join(root, '.crd-ri', 'reports');
// The keys DiscoveryPrefetchKeysCheck treats as standard, and the resource each names.
const STANDARD_KEY_FOR_TYPE = { Patient: 'patient', Encounter: 'encounter', Coverage: 'coverage' };

const app = createWorkbench('REFERENCE_SKIP_BUILD');
let base;
let advertised;

before(async () => {
  // Ask the reference server directly, so the expectations below come from it and not
  // from the workbench. CDS Hooks 2.0 §HTTP Request (https://cds-hooks.hl7.org/2.0/#http-request):
  // "The Discovery endpoint SHALL always be available at {baseUrl}/cds-services."
  let response;
  try {
    response = await fetch(`${serverBase}/cds-services`, { signal: AbortSignal.timeout(10_000) });
  } catch (error) {
    throw new Error(`The CRD reference server is not answering at ${serverBase} (${error.message}); `
      + 'start it with: bash scripts/crd-reference-server.sh start');
  }
  assert.equal(response.status, 200, `reference server discovery returned HTTP ${response.status}`);
  advertised = (await response.json()).services;
  assert.ok(Array.isArray(advertised) && advertised.length > 0, 'the reference server advertises no services');
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  base = await app.start(app.build(), join(root, '.crd-ri', 'workbench.log'),
    ['--workbench.custom-endpoints.enabled=true']);
}, { timeout: 600_000 });

after(() => app.stop());

async function api(path, options) {
  const response = await fetch(`${base}${path}`, { ...options, signal: AbortSignal.timeout(120_000) });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}: ${await response.text()}`);
  return response.json();
}

// Runs a sample against the reference server as a customEndpoint and returns its JSON report.
async function run(name, sampleId, endpoint = { authType: 'NONE' }) {
  const { runId } = await api('/api/runs', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sampleId, customEndpoint: { baseUrl: serverBase, ...endpoint } }),
  });
  const report = await api(`/api/runs/${encodeURIComponent(runId)}/report?format=json`);
  writeFileSync(join(out, `${name}.json`), JSON.stringify(report, null, 2));
  return report;
}

const step = (report, id) => report.steps.find(s => s.stepId === id) ?? assert.fail(`no ${id} step`);
const fails = report => report.findings.filter(f => f.severity === 'FAIL').map(f => `${f.checkId}: ${f.title}`);
const hookExchange = report => step(report, 'hook-request').details.exchanges?.at(-1)
  ?? assert.fail('the hook-request step recorded no exchange');
const describe = report => `${report.verdict.status} at ${report.verdict.brokeAt ?? '-'}; FAIL: ${fails(report).join('; ') || 'none'}`;
const failEvidence = report => report.findings.filter(f => f.severity === 'FAIL')
  .map(f => `${f.checkId}:\n${f.evidence}`).join('\n\n');

test('discovery lists exactly the services the reference server advertises', async () => {
  const report = await run('discovery', sampleIds[0]);
  const discovery = step(report, 'discovery');
  assert.equal(discovery.status, 'passed', describe(report));
  const exchange = discovery.details.exchanges.at(-1);
  assert.equal(exchange.method, 'GET');
  assert.equal(exchange.url, `${serverBase}/cds-services`);
  assert.equal(exchange.status, 200);
  // CDS Hooks 2.0 §Response (#response): "an object containing a list of CDS Services",
  // each with an id, a hook and an OPTIONAL prefetch object of key/FHIR-query pairs.
  const view = service => ({ id: service.id, hook: service.hook,
    prefetchKeys: Object.keys(service.prefetch ?? {}).sort() });
  assert.deepEqual(discovery.details.services, advertised.map(view));
  const services = report.findings.find(f => f.checkId === 'discovery.services');
  assert.equal(services?.severity, 'PASS', `discovery.services: ${services?.title}`);
});

test('discovery.prefetch-keys reports the server\'s own prefetch templates', async () => {
  const report = await run('prefetch-keys', sampleIds[0]);
  // CDS Hooks 2.0 §Prefetch Template (#prefetch-template): a template is a FHIR read or
  // search, and discovery's prefetch field gives "a prefetch key for each one". CRD 2.0.1
  // §Additional Data Retrieval (foundation.html#additional-data-retrieval): clients
  // "SHOULD NOT expect standardized prefetch key names" and SHALL take them from discovery.
  // So every key outside the workbench's standard three must be reported, with the
  // standard key for the resource type its query asks for, or none.
  const expected = advertised.flatMap(service => Object.entries(service.prefetch ?? {})
    .filter(([key]) => !Object.values(STANDARD_KEY_FOR_TYPE).includes(key))
    .map(([key, template]) => {
      const type = template.trim().split(/[/?]/)[0];
      return `${service.id}: "${key}" = ${template.trim()} => ${STANDARD_KEY_FOR_TYPE[type] ?? '(none)'}`;
    })).sort();
  const finding = report.findings.find(f => f.checkId === 'discovery.prefetch-keys');
  assert.ok(finding, 'no discovery.prefetch-keys finding');
  if (expected.length === 0) {
    assert.equal(finding.severity, 'PASS', finding.title);
    return;
  }
  assert.equal(finding.severity, 'INFO', finding.title);
  // The evidence lists "<service>: "<key>" = <template>  =>  <standard>" under "mapped to
  // standard keys:" and "<service>: "<key>" = <template>" under "no standard equivalent:".
  let section;
  const reported = [];
  for (const line of finding.evidence.split('\n')) {
    if (!line.startsWith('  ')) {
      section = line.trim();
      continue;
    }
    const [entry, standard] = line.trim().split('  =>  ');
    reported.push(`${entry} => ${section === 'no standard equivalent:' ? '(none)' : standard}`);
  }
  assert.deepEqual(reported.sort(), expected);
});

for (const sampleId of sampleIds) {
  const metadata = JSON.parse(readFileSync(join(samplesDir, sampleId, 'metadata.json'), 'utf8'));
  const request = JSON.parse(readFileSync(join(samplesDir, sampleId, 'request.json'), 'utf8'));
  const withoutData = Object.keys(request.prefetch ?? {}).length === 0 && !request.fhirServer;
  test(`${sampleId} (${metadata.hook}) with authType NONE gets the verdict the server's answer means`, async () => {
    const report = await run(`sample-${sampleId}`, sampleId);
    const service = advertised.find(s => s.hook === metadata.hook);
    if (!service) {
      // Not a sample the server supports: the workbench must say so at discovery.
      assert.equal(step(report, 'discovery').status, 'failed', describe(report));
      assert.equal(report.verdict.status, 'FAIL', describe(report));
      return;
    }
    // Authenticate has nothing to do without credentials (#136): it must pass either way.
    assert.equal(step(report, 'authenticate').status, 'passed', describe(report));
    const exchange = hookExchange(report);
    // CDS Hooks 2.0 §Calling a CDS Service: POST {baseUrl}/cds-services/{service.id}.
    assert.equal(exchange.method, 'POST');
    assert.equal(exchange.url, `${serverBase}/cds-services/${service.id}`);
    assert.equal(exchange.requestHeaders.Authorization, undefined, 'authType NONE sent an Authorization header');
    if (withoutData) {
      // CDS Hooks 2.0 §Prefetch Template (#prefetch-template): a service that cannot reach a
      // FHIR server and lacks the prefetch it needs "SHALL respond with an HTTP 412". The
      // reference server answers 400; either way it is an error, so the run must not pass.
      assert.ok(exchange.status >= 400 && exchange.status < 500, `hook returned HTTP ${exchange.status}`);
      assert.equal(step(report, 'hook-request').status, 'failed', describe(report));
      assert.equal(report.verdict.status, 'FAIL', describe(report));
      return;
    }
    // CDS Hooks 2.0 §CDS Service Response (#cds-service-response): success is "a 200 HTTP
    // response with an object containing a cards array". A healthy server that needs no
    // auth gets PASS, with no FAIL findings.
    assert.equal(exchange.status, 200, describe(report));
    assert.ok(Array.isArray(JSON.parse(exchange.responseBody).cards), 'the 200 response has no cards array');
    assert.deepEqual(fails(report), [], failEvidence(report));
    assert.equal(report.verdict.status, 'PASS', describe(report));
    assert.ok(report.steps.every(s => s.status === 'passed'), describe(report));
  });
}

test('a credential the server does not require is sent, and the run still passes', async () => {
  // A throwaway key made for this run; the server never checks it.
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const sampleId = sampleIds.find(id => {
    const request = JSON.parse(readFileSync(join(samplesDir, id, 'request.json'), 'utf8'));
    return Object.keys(request.prefetch ?? {}).length > 0 && advertised.some(s => s.hook === request.hook);
  });
  const report = await run('unrequired-credential', sampleId, {
    authType: 'CDS_HOOKS_JWT', clientId: 'reference-run-client', keyId: 'reference-run-key', credential: pem,
  });
  // CDS Hooks 2.0 §Trusting CDS Clients (#trusting-cds-clients): a request "to a CDS Service
  // which requires authentication ... MUST include an Authorization header presenting the
  // JWT as a Bearer token". This server requires none, so the header must not hurt.
  const authenticate = step(report, 'authenticate');
  assert.equal(authenticate.status, 'passed', describe(report));
  assert.equal(authenticate.details.jwtHeader?.kid, 'reference-run-key');
  const sent = hookExchange(report).requestHeaders.Authorization;
  assert.ok(sent?.length === 1 && /^Bearer \S/.test(sent[0]), `Authorization sent: ${JSON.stringify(sent)}`);
  assert.equal(hookExchange(report).status, 200, describe(report));
  assert.deepEqual(fails(report), [], failEvidence(report));
  assert.equal(report.verdict.status, 'PASS', describe(report));
  assert.ok(!JSON.stringify(report).includes(pem.split('\n')[1]), 'the report contains the private key');
});
