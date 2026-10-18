import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseMutations, readFloor, score, summary } from './mutation-summary.mjs';
import { root } from './ci-local.mjs';

const mutation = (status, line, description = 'negated conditional') =>
  `<mutation detected='${status === 'KILLED' || status === 'TIMED_OUT'}' status='${status}' numberOfTestsRun='1'>`
  + '<sourceFile>LatencyCheck.java</sourceFile>'
  + '<mutatedClass>io.github.dflippojr.payerworkbench.diagnostics.LatencyCheck</mutatedClass>'
  + '<mutatedMethod>evaluate</mutatedMethod><methodDescription>()V</methodDescription>'
  + `<lineNumber>${line}</lineNumber>`
  + '<mutator>org.pitest.mutationtest.engine.gregor.mutators.NegateConditionalsMutator</mutator>'
  + `<description>${description}</description></mutation>`;
const report = (...mutations) => `<?xml version="1.0" encoding="UTF-8"?>\n<mutations partial="true">\n${mutations.join('\n')}\n</mutations>`;

test('the score is detected over all mutants, rounded down like pitest', () => {
  const mutations = parseMutations(report(mutation('KILLED', 1), mutation('TIMED_OUT', 2), mutation('SURVIVED', 3)));
  assert.equal(score(mutations), 66);
  assert.deepEqual(mutations.map(m => m.status), ['KILLED', 'TIMED_OUT', 'SURVIVED']);
  assert.equal(mutations[0].mutator, 'NegateConditionalsMutator');
});

test('surviving and uncovered mutants are listed, killed ones are not', () => {
  const { markdown, passed } = summary(parseMutations(report(
    mutation('KILLED', 10), mutation('SURVIVED', 42, 'changed &lt;= to &lt; | boundary'), mutation('NO_COVERAGE', 7))), 30);
  assert.ok(passed);
  assert.match(markdown, /\*\*Score 33%\*\* \(1 of 3 mutants detected\); floor 30%: passed/);
  assert.match(markdown, /### Surviving mutants \(1\)/);
  assert.match(markdown, /\| LatencyCheck\.java:42 \| `evaluate` \| NegateConditionalsMutator \| changed <= to < \\\| boundary \|/);
  assert.match(markdown, /### Mutants no test reaches \(1\)\n\n.*\n.*\n\| LatencyCheck\.java:7 /);
  assert.doesNotMatch(markdown, /LatencyCheck\.java:10 /);
});

test('a score below the floor fails', () => {
  const { markdown, passed } = summary(parseMutations(report(mutation('KILLED', 1), mutation('SURVIVED', 2))), 51);
  assert.equal(passed, false);
  assert.match(markdown, /floor 51%: \*\*FAILED\*\*/);
});

test('an empty report is an error, not a pass', () => {
  assert.throws(() => score(parseMutations(report())), /no mutations/);
});

test('the floor is read from the diagnostics pom', () => {
  const floor = readFloor(readFileSync(join(root, 'diagnostics', 'pom.xml'), 'utf8'));
  assert.ok(Number.isInteger(floor) && floor > 0 && floor <= 100, `floor ${floor}`);
  assert.throws(() => readFloor('<project/>'), /no <pitest.mutation.floor>/);
});
