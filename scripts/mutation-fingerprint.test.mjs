import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fingerprint, inputFiles } from './mutation-fingerprint.mjs';
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
    'diagnostics/src/test/java/CheckTest.java': 'class CheckTest {}',
    'app/pom.xml': pom('app', 'diagnostics'),
    'app/src/main/java/App.java': 'class App {}',
  };
  for (const name of ['install-crd-router.sh', 'mutation.sh', 'mutation-summary.mjs', 'mutation-fingerprint.mjs']) {
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
      'diagnostics/pom.xml', 'diagnostics/src/main/java/Check.java', 'diagnostics/src/test/java/CheckTest.java',
      'mvnw',
      'payers/pom.xml', 'payers/src/main/java/Payer.java',
      'pom.xml',
      'samples/pom.xml', 'samples/src/main/resources/sample.json',
      'scripts/install-crd-router.sh', 'scripts/mutation-fingerprint.mjs', 'scripts/mutation-summary.mjs', 'scripts/mutation.sh',
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

test('an edit to any input, or another JDK, changes the fingerprint; other files do not', () => {
  const dir = fakeRepo();
  try {
    const before = fingerprint(dir, 'openjdk 21.0.5');
    for (const path of inputFiles(dir)) {
      const original = readFileSync(join(dir, path));
      writeFileSync(join(dir, path), Buffer.concat([original, Buffer.from('\n')]));
      assert.notEqual(fingerprint(dir, 'openjdk 21.0.5'), before, `editing ${path} kept the fingerprint`);
      writeFileSync(join(dir, path), original);
    }
    assert.notEqual(fingerprint(dir, 'openjdk 25.0.1'), before, 'another JDK kept the fingerprint');
    writeFileSync(join(dir, 'samples/src/main/resources/new.json'), '{}');
    assert.notEqual(fingerprint(dir, 'openjdk 21.0.5'), before, 'a new sample kept the fingerprint');
    rmSync(join(dir, 'samples/src/main/resources/new.json'));
    writeFileSync(join(dir, 'app/src/main/java/App.java'), 'class App { int changed; }');
    writeFileSync(join(dir, 'core/src/test/java/CoreTest.java'), 'class CoreTest { int changed; }');
    assert.equal(fingerprint(dir, 'openjdk 21.0.5'), before, 'a file diagnostics does not use changed the fingerprint');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// mutation.sh with a stub mvnw that records its calls and writes a one-mutant report.
function runMutationSh(dir) {
  writeFileSync(join(dir, 'mvnw'), `#!/bin/sh
echo "$*" >> "$(dirname "$0")/mvnw.calls"
case "$*" in *mutation*)
  mkdir -p diagnostics/target/pit-reports
  echo "<mutations><mutation detected='true' status='KILLED'><sourceFile>Check.java</sourceFile><lineNumber>1</lineNumber></mutation></mutations>" > diagnostics/target/pit-reports/mutations.xml;;
esac
`);
  chmodSync(join(dir, 'mvnw'), 0o755);
  const result = spawnSync('bash', [join(dir, 'scripts', 'mutation.sh')], {
    encoding: 'utf8', env: { ...process.env, MUTATION_REUSE: 'true', GITHUB_STEP_SUMMARY: '' },
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const calls = join(dir, 'mvnw.calls');
  const ran = existsSync(calls);
  rmSync(calls, { force: true });
  return ran;
}

test('mutation.sh reuses a cached report only when it was produced from the same inputs', () => {
  const dir = fakeRepo();
  try {
    assert.equal(runMutationSh(dir), true, 'the first run must analyse');
    assert.equal(runMutationSh(dir), false, 'unchanged inputs must reuse the report');
    writeFileSync(join(dir, 'payers/src/main/java/Payer.java'), 'class Payer { int changed; }');
    assert.equal(runMutationSh(dir), true, 'a mock payer edit must analyse again');
    assert.equal(runMutationSh(dir), false);
    copyFileSync(join(dir, 'pom.xml'), join(dir, 'diagnostics/target/pit-reports/fingerprint'));
    assert.equal(runMutationSh(dir), true, 'a report with another fingerprint must not be reused');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function assertMutationJobKeyedByFingerprint(workflow) {
  const job = /\n {2}mutation:\n([\s\S]*?)\n {2}\S/.exec(workflow.replaceAll('\r\n', '\n'))?.[1] ?? '';
  assert.match(job, /- name: .*\n\s+id: mutation-fingerprint\n\s+run: node scripts\/mutation-fingerprint\.mjs >> "\$\{GITHUB_OUTPUT:-\/dev\/stdout\}"/);
  assert.match(job, /key: pitest-diagnostics-\$\{\{ steps\.mutation-fingerprint\.outputs\.fingerprint \}\}\n/);
  assert.doesNotMatch(job, /hashFiles/, 'the key must not list inputs by hand');
}

test('CI keys the cached mutation report by the fingerprint', () => {
  assertMutationJobKeyedByFingerprint(readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8'));
});

// A Windows checkout with core.autocrlf=true has CRLF line endings (.gitattributes is * text=auto).
test('the workflow check reads LF and CRLF checkouts alike', () => {
  const lf = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8').replaceAll('\r\n', '\n');
  assertMutationJobKeyedByFingerprint(lf);
  assertMutationJobKeyedByFingerprint(lf.replaceAll('\n', '\r\n'));
});
