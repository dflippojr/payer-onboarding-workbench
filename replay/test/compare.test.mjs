// compareRuns is pure logic: evaluate static/compare.js alone, with no DOM and no browser.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const context = {};
runInNewContext(readFileSync(new URL('../../workbench-app/src/main/resources/static/compare.js', import.meta.url), 'utf8'), context);
const { compareRuns } = context.PayerWorkbench;

const STEPS = ['resolve-connection', 'discovery', 'authenticate', 'hook-request', 'parse-response', 'diagnostics'];
function stepStatus(index, broke) {
  const at = STEPS.indexOf(broke);
  if (at < 0 || index < at) return 'passed';
  return index === at || STEPS[index] === 'diagnostics' ? 'failed' : 'skipped';
}
const flow = (id, findings, broke) => ({ runId: id, payerId: 'synthetic-payer', environment: 'SANDBOX',
  steps: STEPS.map((stepId, i) => ({ stepId, details: { status: stepStatus(i, broke) }, elapsed: 0.01, summary: `${stepId} ${id}` })),
  findings: Object.entries(findings).flatMap(([checkId, severities]) =>
    [].concat(severities).map(severity => ({ severity, checkId, title: `${checkId} title` }))) });
const plain = value => JSON.parse(JSON.stringify(value));
const ids = list => list.map(c => `${c.checkId}:${c.before}->${c.after}`);

test('comparison of identical runs leaves every check unchanged', () => {
  const run = flow('same', { 'a.pass': 'PASS', 'b.warn': 'WARN', 'c.info': 'INFO' });
  const diff = plain(compareRuns(run, run));
  assert.deepEqual(diff.verdict, { before: 'PASS_WITH_WARNINGS', after: 'PASS_WITH_WARNINGS', change: 'unchanged' });
  assert.deepEqual(diff.brokeAt, { before: null, after: null });
  assert.deepEqual(diff.steps, []);
  assert.deepEqual(diff.worse, []);
  assert.deepEqual(diff.better, []);
  assert.deepEqual(diff.oneSided, []);
  assert.deepEqual(ids(diff.unchanged), ['b.warn:WARN->WARN', 'c.info:INFO->INFO', 'a.pass:PASS->PASS']);
});

test('comparison groups a fixed FAIL, a new FAIL, WARN to FAIL and FAIL to PASS in severity order', () => {
  const before = flow('before', { 'fixed.fail': 'FAIL', 'warn.to.fail': 'WARN', 'new.fail': 'PASS',
    'fail.to.warn': 'FAIL', 'same.warn': 'WARN' });
  const after = flow('after', { 'fixed.fail': 'PASS', 'warn.to.fail': 'FAIL', 'new.fail': 'FAIL',
    'fail.to.warn': 'WARN', 'same.warn': 'WARN' });
  const diff = plain(compareRuns(before, after));
  assert.deepEqual(diff.verdict, { before: 'FAIL', after: 'FAIL', change: 'unchanged' });
  assert.deepEqual(ids(diff.worse), ['warn.to.fail:WARN->FAIL', 'new.fail:PASS->FAIL']);
  assert.deepEqual(ids(diff.better), ['fail.to.warn:FAIL->WARN', 'fixed.fail:FAIL->PASS']);
  assert.deepEqual(ids(diff.unchanged), ['same.warn:WARN->WARN']);
  assert.equal(diff.worse[1].title, 'new.fail title');
});

test('comparison lists a check reported by only one run separately, not as better, worse or unchanged', () => {
  const before = flow('before', { 'gone.fail': 'FAIL', 'gone.pass': 'PASS', 'same.pass': 'PASS' });
  const after = flow('after', { 'added.warn': 'WARN', 'added.pass': 'PASS', 'same.pass': 'PASS' });
  const diff = plain(compareRuns(before, after));
  assert.deepEqual(diff.worse, []);
  assert.deepEqual(diff.better, []);
  assert.deepEqual(ids(diff.unchanged), ['same.pass:PASS->PASS']);
  assert.deepEqual(ids(diff.oneSided),
    ['gone.fail:FAIL->null', 'added.warn:null->WARN', 'added.pass:null->PASS', 'gone.pass:PASS->null']);
  assert.deepEqual(diff.verdict, { before: 'FAIL', after: 'PASS_WITH_WARNINGS', change: 'better' });
});

test('comparison uses the most severe finding when a check has several', () => {
  const before = flow('before', { 'multi.check': ['PASS', 'WARN', 'INFO'] });
  const after = flow('after', { 'multi.check': ['PASS', 'FAIL', 'WARN'] });
  assert.deepEqual(ids(plain(compareRuns(before, after)).worse), ['multi.check:WARN->FAIL']);
  assert.deepEqual(ids(plain(compareRuns(after, after)).unchanged), ['multi.check:FAIL->FAIL']);
});

test('comparison reports the broke-at step moving or disappearing and the steps that changed', () => {
  const healthy = flow('healthy', { 'x.pass': 'PASS' });
  const discovery = flow('discovery', { 'discovery.reachable': 'FAIL' }, 'discovery');
  const auth = flow('auth', { 'auth.token': 'FAIL' }, 'authenticate');
  const moved = plain(compareRuns(discovery, auth));
  assert.deepEqual(moved.brokeAt, { before: 'discovery', after: 'authenticate' });
  assert.deepEqual(moved.steps, [
    { stepId: 'discovery', before: 'failed', after: 'passed' },
    { stepId: 'authenticate', before: 'skipped', after: 'failed' }]);
  const fixed = plain(compareRuns(discovery, healthy));
  assert.deepEqual(fixed.brokeAt, { before: 'discovery', after: null });
  assert.deepEqual(fixed.verdict, { before: 'FAIL', after: 'PASS', change: 'better' });
  assert.equal(fixed.steps.length, 5);
  assert.deepEqual(fixed.better, []);
  assert.deepEqual(ids(fixed.oneSided), ['discovery.reachable:FAIL->null', 'x.pass:null->PASS']);
  const broken = plain(compareRuns(healthy, discovery));
  assert.deepEqual(broken.brokeAt, { before: null, after: 'discovery' });
  assert.deepEqual(broken.verdict, { before: 'PASS', after: 'FAIL', change: 'worse' });
  assert.deepEqual(broken.worse, []);
  assert.deepEqual(ids(broken.oneSided), ['discovery.reachable:null->FAIL', 'x.pass:PASS->null']);
  assert.equal(plain(compareRuns(healthy, flow('no-findings', {}, 'hook-request'))).verdict.after, 'FAIL');
});
