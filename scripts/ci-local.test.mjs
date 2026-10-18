import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
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
  assert.match(header, /^on:\n {2}pull_request_target:\n {4}types: \[opened, synchronize, reopened, edited, labeled, unlabeled\]\n\n/m);
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
