#!/usr/bin/env node
// The full CI gate on your machine: npm run ci:local. Node 22+, JDK 21 on JAVA_HOME,
// Docker running (crd-reference job), and bash (Git Bash on Windows). Runs every run: step of .github/workflows/ci.yml in
// the same order through bash, stops at the first failure, still runs the
// if: always() steps (so the UI instance is stopped), then exits non-zero.
// scripts/ci-local.test.mjs fails when this list drifts from ci.yml. The hl7-validator
// steps also need curl and sha256sum, and the first run downloads about 3.5 GB of FHIR
// packages into ~/.cache/hl7-validator.
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Copied verbatim from ci.yml: name (when the step has one), run, and always for if: always().
export const steps = [
  { name: 'Install fhir-crd-router at the pinned commit', run: 'bash scripts/install-crd-router.sh' },
  { run: './mvnw -B verify' },
  { name: 'Demo tour (reuses the jar built by verify)', run: 'DEMO_SKIP_BUILD=1 node scripts/demo.mjs' },
  { name: 'Install locked UI test dependencies', run: 'npm ci --ignore-scripts' },
  { name: 'Install UI browsers', run: 'node node_modules/@playwright/test/cli.js install --with-deps chromium webkit' },
  { name: 'Verify disposable-instance safety boundaries', run: 'npm run test:ui-instance' },
  { name: 'Disposable synthetic UI journeys (one worker)', run: 'npm run test:ui' },
  { name: 'Stop the owned UI instance even on failure', run: 'node scripts/ui-instance.mjs stop', always: true },
  { name: 'Export the website replay bundle (reuses the jar)', run: 'EXPORT_SKIP_BUILD=1 node scripts/export-replays.mjs' },
  { name: 'Check the leak scanner against the shared redaction corpus', run: 'node --test replay/test/leaks.test.mjs' },
  { name: 'Check the replay bundle', run: 'node --test replay/test/bundle.test.mjs' },
  { name: 'Check the audit reader regression suite', run: 'node --test scripts/audit-reader.test.mjs' },
  {
    name: 'Check the workbench lifecycle regression suite (timeout fails a hung cleanup)',
    run: 'node --experimental-vm-modules --test --test-timeout=10000 scripts/workbench-lifecycle.test.mjs',
  },
  { name: "Check the verify skill's doctor and cleanup", run: 'npm run test:verify' },
  { name: 'Check that npm run ci:local matches this workflow', run: 'node --test scripts/ci-local.test.mjs' },
  // crd-reference job (needs Docker)
  {
    name: 'Start the CRD reference server on loopback (builds the image on a cache miss)',
    run: 'bash scripts/crd-reference-server.sh start',
  },
  { name: 'Install fhir-crd-router at the pinned commit', run: 'bash scripts/install-crd-router.sh' },
  { name: 'Build the workbench jar (tests run in build)', run: './mvnw -B -pl workbench-app -am package -DskipTests' },
  {
    name: 'Reference runs against the CRD reference server',
    run: 'REFERENCE_SKIP_BUILD=1 node --test scripts/reference-runs.mjs',
  },
  { name: 'Stop the CRD reference server even on failure', run: 'bash scripts/crd-reference-server.sh stop', always: true },
  // hl7-validator job
  { name: 'Download the pinned HL7 validator and FHIR packages (no-op when cached)', run: 'bash scripts/hl7-validator.sh warm' },
  { name: 'Install fhir-crd-router at the pinned commit', run: 'bash scripts/install-crd-router.sh' },
  { name: 'Differential conformance test against the HL7 validator (offline)', run: 'bash scripts/hl7-validator.sh test' },
  // mutation job
  { name: 'Fingerprint the mutation inputs', run: 'node scripts/mutation-fingerprint.mjs >> "${GITHUB_OUTPUT:-/dev/stdout}"' },
  {
    name: 'Check the mutation scripts',
    run: 'node --test scripts/mutation-summary.test.mjs scripts/mutation-fingerprint.test.mjs',
  },
  { name: 'Install fhir-crd-router at the pinned commit', run: 'bash scripts/install-crd-router.sh' },
  {
    name: 'Mutation testing on diagnostics (reuses the cached report when its inputs are unchanged)',
    run: 'bash scripts/mutation.sh',
  },
];

const bash = command => {
  const result = spawnSync('bash', ['-c', command], { cwd: root, stdio: 'inherit' });
  if (result.error) console.error(`    ${result.error.message}`);
  return result.status ?? 1;
};

// Returns the name of the first failed step, or null when every step passed.
export function runSteps(list = steps, exec = bash, log = console.log) {
  let failed = null;
  for (const [index, step] of list.entries()) {
    const label = step.name ?? step.run;
    if (failed && !step.always) {
      log(`\n--  ${index + 1}/${list.length} skipped: ${label}`);
      continue;
    }
    log(`\n==> ${index + 1}/${list.length} ${label}\n    $ ${step.run}`);
    const started = Date.now();
    const status = exec(step.run);
    log(`    ${status === 0 ? 'ok' : `FAILED (exit ${status})`} in ${Math.round((Date.now() - started) / 1000)} s`);
    if (status !== 0) failed ??= label;
  }
  return failed;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const failed = runSteps();
  console.log(failed ? `\nci:local FAILED at: ${failed}` : '\nci:local passed: every ci.yml step succeeded');
  process.exitCode = failed ? 1 : 0;
}
