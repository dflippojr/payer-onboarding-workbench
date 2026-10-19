import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { inputFiles, partitions } from './mutation-fingerprint.mjs';
import { root } from './ci-local.mjs';

const pom = (artifactId, ...dependencies) => `<project>
  <parent><artifactId>parent</artifactId></parent>
  <artifactId>${artifactId}</artifactId>
  <properties><pitest.mutation.floor>50</pitest.mutation.floor></properties>
  <dependencies>${dependencies.map(d => `<dependency><artifactId>${d}</artifactId><scope>test</scope></dependency>`).join('')}</dependencies>
</project>`;

// A small reactor shaped like this repo's: diagnostics needs core, and payers and samples for its tests.
function fakeRepo() {
  const dir = mkdtempSync(join(tmpdir(), 'mutation-fingerprint-'));
  const files = {
    'pom.xml': '<project><modules><module>core</module><module>payers</module><module>samples</module>'
      + '<module>diagnostics</module><module>app</module></modules></project>',
    'mvnw': '#!/bin/sh\n',
    '.mvn/wrapper/maven-wrapper.properties': 'distributionUrl=maven-3.9.9\n',
    'core/pom.xml': pom('core'),
    'core/src/main/java/Core.java': 'class Core {}',
    'core/src/test/java/CoreTest.java': 'class CoreTest {}',
    'payers/pom.xml': pom('payers', 'core'),
    'payers/src/main/java/Payer.java': 'class Payer {}',
    'samples/pom.xml': pom('samples'),
    'samples/src/main/resources/sample.json': '{}',
    'diagnostics/pom.xml': pom('diagnostics', 'core', 'payers', 'samples', 'jackson-databind'),
    'diagnostics/src/main/java/Check.java': 'class Check {}',
    'diagnostics/src/main/java/Support.java': 'class Support {}',
    'diagnostics/src/test/java/CheckTest.java': 'class CheckTest {}',
    'app/pom.xml': pom('app', 'diagnostics'),
    'app/src/main/java/App.java': 'class App {}',
  };
  for (const name of ['install-crd-router.sh', 'mutation.sh', 'mutation-summary.mjs', 'mutation-merge.mjs', 'mutation-fingerprint.mjs']) {
    files[`scripts/${name}`] = readFileSync(join(root, 'scripts', name), 'utf8');
  }
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}

test('the inputs are the diagnostics module, its reactor dependencies, Maven and the mutation scripts', () => {
  const dir = fakeRepo();
  try {
    assert.deepEqual(inputFiles(dir), [
      '.mvn/wrapper/maven-wrapper.properties',
      'core/pom.xml', 'core/src/main/java/Core.java',
      'diagnostics/pom.xml', 'diagnostics/src/main/java/Check.java', 'diagnostics/src/main/java/Support.java',
      'diagnostics/src/test/java/CheckTest.java',
      'mvnw',
      'payers/pom.xml', 'payers/src/main/java/Payer.java',
      'pom.xml',
      'samples/pom.xml', 'samples/src/main/resources/sample.json',
      'scripts/install-crd-router.sh', 'scripts/mutation-fingerprint.mjs', 'scripts/mutation-merge.mjs',
      'scripts/mutation-summary.mjs', 'scripts/mutation.sh',
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('in this repo the inputs include mock-payers, samples and the Maven wrapper', () => {
  const files = inputFiles(root);
  for (const expected of ['mock-payers/pom.xml', 'samples/pom.xml', 'workbench-core/pom.xml', 'diagnostics/pom.xml',
    'pom.xml', 'mvnw', '.mvn/wrapper/maven-wrapper.properties', 'scripts/install-crd-router.sh']) {
    assert.ok(files.includes(expected), `${expected} is not an input`);
  }
  for (const module of ['mock-payers', 'samples', 'workbench-core']) {
    assert.ok(files.some(f => f.startsWith(`${module}/src/main/`)), `no ${module}/src/main file is an input`);
  }
  assert.ok(files.some(f => f.startsWith('diagnostics/src/test/')), 'the diagnostics tests are not an input');
  assert.ok(!files.some(f => f.startsWith('workbench-app/')), 'workbench-app is not a diagnostics dependency');
});

const RUNTIME = 'openjdk 21.0.5';
const keys = dir => Object.fromEntries(partitions(dir, RUNTIME).map(({ name, key }) => [name, key]));

test('every diagnostics class is a partition, with the pitest pattern for its classes', () => {
  const dir = fakeRepo();
  try {
    assert.deepEqual(partitions(dir, RUNTIME).map(({ name, target }) => [name, target]), [
      ['Check', 'Check*'],
      ['Support', 'Support*'],
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('in this repo every diagnostics class is a partition, and package-info is not', () => {
  const found = partitions(root, RUNTIME);
  assert.ok(found.some(({ name, target }) => name === 'ClockSkewCheck'
    && target === 'io.github.dflippojr.payerworkbench.diagnostics.ClockSkewCheck*'));
  assert.ok(found.some(({ name }) => name === 'DiagnosticEngine'));
  assert.ok(!found.some(({ name }) => name === 'package-info'));
  assert.equal(new Set(found.map(({ name }) => name)).size, found.length, 'partition names must be unique');
});

test('editing one check changes only that check\'s partition key', () => {
  const dir = fakeRepo();
  try {
    const before = keys(dir);
    writeFileSync(join(dir, 'diagnostics/src/main/java/Check.java'), 'class Check { int changed; }');
    const after = keys(dir);
    assert.notEqual(after.Check, before.Check, 'editing the check kept its key');
    assert.equal(after.Support, before.Support, 'editing one check invalidated another partition');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an edit to a shared class, a diagnostics test, the pom, an upstream module or the JDK invalidates every partition', () => {
  const dir = fakeRepo();
  try {
    const before = keys(dir);
    for (const path of ['diagnostics/src/main/java/Support.java', 'diagnostics/src/test/java/CheckTest.java',
      'diagnostics/pom.xml', 'payers/src/main/java/Payer.java', 'scripts/mutation-merge.mjs']) {
      const original = readFileSync(join(dir, path));
      writeFileSync(join(dir, path), Buffer.concat([original, Buffer.from('\n')]));
      const after = keys(dir);
      for (const name of Object.keys(before)) assert.notEqual(after[name], before[name], `editing ${path} kept ${name}`);
      writeFileSync(join(dir, path), original);
    }
    const jdk = Object.fromEntries(partitions(dir, 'openjdk 25.0.1').map(({ name, key }) => [name, key]));
    for (const name of Object.keys(before)) assert.notEqual(jdk[name], before[name], `another JDK kept ${name}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('edits outside the diagnostics inputs change no partition key', () => {
  const dir = fakeRepo();
  try {
    const before = keys(dir);
    writeFileSync(join(dir, 'app/src/main/java/App.java'), 'class App { int changed; }');
    writeFileSync(join(dir, 'core/src/test/java/CoreTest.java'), 'class CoreTest { int changed; }');
    assert.deepEqual(keys(dir), before);
    writeFileSync(join(dir, 'samples/src/main/resources/new.json'), '{}');
    assert.notDeepEqual(keys(dir), before, 'a new sample kept the keys');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// mutation.sh with a stub mvnw: each pitest run writes a one-mutant report for the class it was given, and
// the stub records the class pattern. Returns the patterns pitest was asked to analyse in this run.
function runMutationSh(dir) {
  writeFileSync(join(dir, 'mvnw'), `#!/bin/sh
case "$*" in *mutationCoverage*)
  for arg in "$@"; do
    case "$arg" in -Dpit.targetClasses=*) target=$(echo "$arg" | cut -d= -f2-);; esac
  done
  echo "$target" >> "$(dirname "$0")/pitest.calls"
  mkdir -p diagnostics/target/pit-reports
  echo "<mutations><mutation detected='true' status='KILLED'><sourceFile>$target</sourceFile><lineNumber>1</lineNumber></mutation></mutations>" > diagnostics/target/pit-reports/mutations.xml;;
esac
`);
  chmodSync(join(dir, 'mvnw'), 0o755);
  const result = spawnSync('bash', [join(dir, 'scripts', 'mutation.sh')], {
    encoding: 'utf8', env: { ...process.env, GITHUB_STEP_SUMMARY: '' },
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const calls = join(dir, 'pitest.calls');
  const ran = existsSync(calls) ? readFileSync(calls, 'utf8').trim().split('\n').filter(Boolean) : [];
  rmSync(calls, { force: true });
  return ran;
}

test('mutation.sh analyses only the classes whose inputs changed, and merges every class into one report', () => {
  const dir = fakeRepo();
  try {
    assert.deepEqual(runMutationSh(dir), ['Check*', 'Support*'], 'the first run must analyse every class');
    const merged = readFileSync(join(dir, 'diagnostics/target/pit-reports/mutations.xml'), 'utf8');
    assert.equal(merged.match(/<mutation /g).length, 2, 'the merged report must hold every class\'s mutants');
    assert.deepEqual(runMutationSh(dir), [], 'unchanged inputs must analyse nothing');
    writeFileSync(join(dir, 'diagnostics/src/main/java/Check.java'), 'class Check { int changed; }');
    assert.deepEqual(runMutationSh(dir), ['Check*'], 'touching one check must analyse that check only');
    writeFileSync(join(dir, 'payers/src/main/java/Payer.java'), 'class Payer { int changed; }');
    assert.deepEqual(runMutationSh(dir), ['Check*', 'Support*'], 'an upstream edit must analyse every class');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function assertMutationJobCachesThePitestHistory(workflow) {
  const job = /\n {2}mutation:\n([\s\S]*?)\n {2}\S/.exec(workflow.replaceAll('\r\n', '\n'))?.[1] ?? '';
  assert.match(job, /- name: .*\n\s+id: pitest-cache\n\s+uses: actions\/cache\/restore@v6\n\s+with:\n\s+path: diagnostics\/target\/pit-history\n/);
  assert.match(job, /key: pitest-history-\$\{\{ hashFiles\('diagnostics\/pom\.xml', 'diagnostics\/src\/\*\*'\) \}\}-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}\n/);
  assert.match(job, /restore-keys: \|\n\s+pitest-history-\$\{\{ hashFiles\('diagnostics\/pom\.xml', 'diagnostics\/src\/\*\*'\) \}\}-\n\s+pitest-history-\n/);
  assert.match(job, /- name: .*\n\s+if: always\(\)\n\s+uses: actions\/cache\/save@v6\n\s+with:\n\s+path: diagnostics\/target\/pit-history\n\s+key: \$\{\{ steps\.pitest-cache\.outputs\.cache-primary-key \}\}\n/);
  assert.doesNotMatch(job, /MUTATION_REUSE|id: mutation-fingerprint/, 'the job still uses the whole-report cache');
}

test('CI restores the pitest history by the diagnostics sources, with a prefix fallback, and saves it', () => {
  assertMutationJobCachesThePitestHistory(readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8'));
});

// A Windows checkout with core.autocrlf=true has CRLF line endings (.gitattributes is * text=auto).
test('the workflow check reads LF and CRLF checkouts alike', () => {
  const lf = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8').replaceAll('\r\n', '\n');
  assertMutationJobCachesThePitestHistory(lf);
  assertMutationJobCachesThePitestHistory(lf.replaceAll('\n', '\r\n'));
});
