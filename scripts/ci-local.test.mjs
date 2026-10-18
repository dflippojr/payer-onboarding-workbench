import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { root, runSteps, steps } from './ci-local.mjs';

// Just enough YAML for ci.yml: jobs, needs, if, and each step's name, if and run
// (inline or a | block). Anything else in a step is ignored.
function parseWorkflow(text) {
  const jobs = {};
  let inJobs = false, job, step, block;
  for (const line of text.replaceAll('\r\n', '\n').split('\n')) {
    if (block) {
      if (!line.trim() || line.startsWith(block.indent)) {
        block.lines.push(line.slice(block.indent.length));
        continue;
      }
      block.step.run = block.lines.join('\n').trimEnd();
      block = null;
    }
    let match;
    if (/^\S/.test(line)) {
      inJobs = /^jobs:\s*$/.test(line);
      job = step = null;
    } else if (inJobs && (match = /^ {2}([\w-]+):\s*$/.exec(line))) {
      job = jobs[match[1]] = { needs: [], if: undefined, steps: [] };
      step = null;
    } else if (job && (match = /^ {4}needs:\s*\[(.*)\]\s*$/.exec(line))) {
      job.needs = match[1].split(',').map(name => name.trim()).filter(Boolean);
    } else if (job && (match = /^ {4}if:\s*(.+?)\s*$/.exec(line))) {
      job.if = match[1];
    } else if (job && (match = /^ {6}- (.*)$/.exec(line))) {
      job.steps.push(step = {});
      keyValue(step, match[1]);
    } else if (step && (match = /^ {8}(\S.*)$/.exec(line)) && keyValue(step, match[1]) === '|') {
      block = { step, indent: ' '.repeat(10), lines: [] };
    }
  }
  if (block) block.step.run = block.lines.join('\n').trimEnd();
  return jobs;
}
function keyValue(step, text) {
  const match = /^(name|if|run):\s*(.*?)\s*$/.exec(text);
  if (match) step[match[1]] = match[2].replace(/^"(.*)"$/, '$1');
  return match?.[2];
}

const workflow = parseWorkflow(readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8'));

const publisher = parseWorkflow(readFileSync(join(root, '.github', 'workflows', 'publish-replay-bundle.yml'), 'utf8'));
const eligibility = publisher.publish.steps.find(step => step.run);
const ordering = publisher.publish.steps.find(step => step.name === 'Skip a bundle older than the published one');

// Run the actual workflow guards against a real history: previous -> A -> B -> C (main).
// gh only supplies the previous release's manifest; no release is created by these tests.
function publishingHistory(t, mainAt = 'c') {
  const dir = mkdtempSync(join(tmpdir(), 'pw-publish-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  function git(...args) {
    const result = spawnSync('git', args, { cwd: dir, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  }
  git('init', '-b', 'main');
  git('config', 'user.name', 'Synthetic Publisher Test');
  git('config', 'user.email', 'publisher@example.invalid');
  function commit(message) {
    git('commit', '--allow-empty', '-m', message);
    return git('rev-parse', 'HEAD');
  }
  const previous = commit('previous release'), a = commit('A'), b = commit('B'), c = commit('C');
  git('checkout', '-b', 'untrusted', a);
  const other = commit('not on main');
  git('branch', '-f', 'main', mainAt === 'b' ? b : c);
  git('checkout', 'main');
  function guard(step, sha, published, scenario = {}) {
    const output = join(dir, 'output').replaceAll('\\', '/');
    writeFileSync(output, '');
    const result = spawnSync('bash', ['-e', '-o', 'pipefail', '-c',
      `gh() {
        if [[ "$1" == api ]]; then
          case "$RELEASE_STATE" in
            absent) printf 'HTTP/2.0 404 Not Found\\n'; return 1 ;;
            forbidden) printf 'HTTP/2.0 403 Forbidden\\n'; return 1 ;;
            server-error) printf 'HTTP/2.0 500 Internal Server Error\\n'; return 1 ;;
            transport-error) echo 'connection failed' >&2; return 1 ;;
            *) printf 'HTTP/2.0 200 OK\\n'; return 0 ;;
          esac
        fi
        if [[ "$1 $2" == "release download" ]]; then
          case "$MANIFEST_STATE" in
            download-error) echo 'download failed' >&2; return 1 ;;
            truncated) printf '{"gitCommit":"%s"}' "$PUBLISHED_COMMIT"; return 23 ;;
            invalid-json) printf 'not JSON'; return 0 ;;
            missing-commit) printf '{}'; return 0 ;;
            *) printf '{"gitCommit":"%s"}\\n' "$PUBLISHED_COMMIT"; return 0 ;;
          esac
        fi
        echo 'unexpected gh command' >&2; return 99
      }\n` + step.run], {
      cwd: dir, encoding: 'utf8',
      env: { ...process.env, SHA: sha, TAG: 'replay-bundle', PUBLISHED_COMMIT: published, GITHUB_OUTPUT: output,
        RELEASE_STATE: scenario.release ?? 'present', MANIFEST_STATE: scenario.manifest ?? 'valid' },
    });
    return { ...result, skip: readFileSync(output, 'utf8').includes('skip=true') };
  }
  const permits = result => result.status === 0 && !result.skip;
  return { previous, a, b, c, other,
    order: (sha, published, scenario) => guard(ordering, sha, published, scenario),
    accepts: (sha, published) => permits(guard(eligibility, sha, published)) && permits(guard(ordering, sha, published)) };
}

test('publisher accepts successful A when main has advanced to a failing B', t => {
  const history = publishingHistory(t, 'b');
  assert.equal(history.accepts(history.a, history.previous), true);
});

test('publisher accepts successive successful ancestors even after another main push', t => {
  const history = publishingHistory(t);
  assert.equal(history.accepts(history.a, history.previous), true);
  assert.equal(history.accepts(history.b, history.a.slice(0, 12)), true);
});

test('publisher skips an older completion after a newer bundle has published', t => {
  const history = publishingHistory(t);
  assert.equal(history.accepts(history.b, history.previous), true);
  assert.equal(history.accepts(history.a, history.b.slice(0, 12)), false);
  assert.equal(history.accepts(history.c, history.b.slice(0, 12)), true);
});

test('publisher rejects a successful commit outside trusted main history', t => {
  const history = publishingHistory(t);
  assert.equal(history.accepts(history.other, history.previous), false);
});

test('publisher fails closed when an existing newer manifest cannot be downloaded', t => {
  const history = publishingHistory(t);
  for (const manifest of ['download-error', 'truncated']) {
    const result = history.order(history.a, history.b.slice(0, 12), { manifest });
    assert.notEqual(result.status, 0, manifest + ': must fail, not authorize publishing');
  }
});

test('publisher fails closed on invalid or unresolvable published metadata', t => {
  const history = publishingHistory(t);
  for (const [manifest, published] of [
    ['invalid-json', history.b], ['missing-commit', history.b], ['valid', ''],
    ['valid', history.b.slice(0, 12) + '-dirty'], ['valid', 'HEAD'],
    ['valid', '0'.repeat(12)],
  ]) {
    const result = history.order(history.a, published, { manifest });
    assert.notEqual(result.status, 0, manifest + '/' + published + ': must fail closed');
  }
});

test('publisher only bootstraps a release after an explicit not-found response', t => {
  const history = publishingHistory(t);
  const absent = history.order(history.a, '', { release: 'absent', manifest: 'download-error' });
  assert.equal(absent.status, 0, absent.stderr);
  assert.equal(absent.skip, false);
  for (const release of ['forbidden', 'server-error', 'transport-error']) {
    const result = history.order(history.a, history.b.slice(0, 12), { release });
    assert.notEqual(result.status, 0, release + ': must fail closed');
  }
});

test('every run: step in ci.yml has the matching ci:local step, in order', () => {
  const fromWorkflow = Object.entries(workflow).filter(([id]) => id !== 'gate')
    .flatMap(([, job]) => job.steps).filter(step => step.run !== undefined)
    .map(step => {
      assert.ok(step.if === undefined || step.if === 'always()', `ci:local cannot mirror if: ${step.if}`);
      return { ...(step.name ? { name: step.name } : {}), run: step.run, ...(step.if ? { always: true } : {}) };
    });
  assert.ok(fromWorkflow.length > 10, 'parsed too few ci.yml steps; is the parser still right?');
  assert.deepEqual(steps, fromWorkflow);
});

test('the gate job always runs and needs every other job', () => {
  assert.ok(workflow.gate, 'ci.yml has no gate job');
  assert.equal(workflow.gate.if, 'always()');
  assert.deepEqual([...workflow.gate.needs].sort(), Object.keys(workflow).filter(id => id !== 'gate').sort());
});

test('a failure skips later steps but still runs always steps, and is reported', () => {
  const ran = [];
  const failed = runSteps([
    { name: 'one', run: 'a' }, { name: 'two', run: 'b' }, { name: 'three', run: 'c' },
    { name: 'stop', run: 'd', always: true }, { name: 'four', run: 'e' },
  ], run => { ran.push(run); return run === 'b' ? 2 : 0; }, () => {});
  assert.equal(failed, 'two');
  assert.deepEqual(ran, ['a', 'b', 'd']);
});

test('a failing always step after an earlier failure keeps the first failure', () => {
  const failed = runSteps([{ run: 'a' }, { run: 'b', always: true }], () => 1, () => {});
  assert.equal(failed, 'a');
});

test('every step passing reports no failure', () => {
  assert.equal(runSteps([{ run: 'a' }, { run: 'b', always: true }], () => 0, () => {}), null);
});

test('the parser reads block runs, quoted names and job-level settings', () => {
  const jobs = parseWorkflow([
    'on:', '  push:', 'jobs:', '  build:', '    runs-on: ubuntu-latest', '    steps:',
    '      - uses: actions/checkout@v7', '      - name: "Quoted"', '        run: echo one',
    '      - name: Block', '        if: always()', '        run: |', '          echo two', '', '          echo three',
    '  gate:', '    needs: [build, lint]', '    if: always()', '    steps:', '      - run: true', '',
  ].join('\r\n'));
  assert.deepEqual(jobs.build.steps, [{}, { name: 'Quoted', run: 'echo one' },
    { name: 'Block', if: 'always()', run: 'echo two\n\necho three' }]);
  assert.deepEqual(jobs.gate, { needs: ['build', 'lint'], if: 'always()', steps: [{ run: 'true' }] });
});

// The workflow's lines without comment lines, so a key named in a comment doesn't count.
function code(text) {
  return text.replaceAll('\r\n', '\n').split('\n').filter(line => !line.trimStart().startsWith('#')).join('\n') + '\n';
}
const guardSha = /guard-ref: ([0-9a-f]{40})\n/.exec(code(readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8')))?.[1];

test('ci.yml calls the shared gate guard at one full SHA, as an early signal inside gate', () => {
  const ci = code(readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8'));
  assert.ok(guardSha, 'ci.yml has no gate-guard job with a full-SHA guard-ref');
  assert.ok(ci.includes(`  gate-guard:\n`), ci);
  assert.ok(ci.includes(`    uses: dflippojr/.github/.github/workflows/gate-guard.yml@${guardSha}\n`));
  assert.ok(ci.includes('      require-owner-label-actor: true\n'));
  assert.ok(workflow.gate.needs.includes('gate-guard'));
});

test('the trusted gate guard runs from the default branch and runs no pull request code', () => {
  // ci.yml runs on pull_request, so a pull request supplies its own copy of it and can
  // replace its gate-guard job with a green no-op. Under pull_request_target this caller is
  // read from main, and the called workflow only fetches the pull request's commits as git
  // objects; its verdict is the gate-guard check the ruleset requires.
  const target = code(readFileSync(join(root, '.github', 'workflows', 'gate-guard-target.yml'), 'utf8'));
  const [header, jobs] = target.split('\njobs:\n');
  assert.match(header, /^on:\n {2}pull_request_target:\n {4}types: \[opened, synchronize, reopened, edited, labeled, unlabeled, closed\]\n\n/m);
  assert.ok(!/\bpull_request:|workflow_dispatch|workflow_run/.test(target), target);
  assert.match(header, /^permissions:\n {2}contents: read\n {2}issues: read\n {2}pull-requests: read\n {2}checks: write\n\n/m);
  assert.ok(header.includes('group: gate-guard-target-${{ github.event.pull_request.head.sha }}\n'));
  assert.ok(header.includes('cancel-in-progress: true\n'));
  assert.equal(jobs.trimEnd() + '\n', [
    '  judge:',
    `    uses: dflippojr/.github/.github/workflows/gate-guard-target.yml@${guardSha}`,
    '    with:',
    `      guard-ref: ${guardSha}`,
    '',
  ].join('\n'), 'the only job calls the pinned trusted guard with the same SHA as ci.yml');
});
