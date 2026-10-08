import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { options, review } from './audit-reader.mjs';

const event = (runId = 'run-one', action = 'run.completed', occurredAt = '2026-10-08T12:00:00Z') =>
  ({ schemaVersion: 1, eventId: 'synthetic-event', runId, action, occurredAt });
const line = e => 'INFO logger : audit ' + JSON.stringify(e);

test('inclusive time, run and action filters ignore unrelated logs', async () => {
  const output = [];
  const filters = options(['capture.log', '--run', 'run-one', '--action', 'run.completed',
    '--since', '2026-10-08T12:00:00Z', '--until', '2026-10-08T12:00:00Z']);
  assert.equal(await review(['step runId=run-one', line(event()), line(event('other')),
    line(event('run-one', 'report.rendered')), line(event('run-one', 'run.completed', '2026-10-08T12:00:01Z'))], filters, x => output.push(x)), 0);
  assert.deepEqual(output.map(JSON.parse), [event()]);
});
test('malformed lines counted without echo and empty input works', async () => {
  const output = [];
  assert.equal(await review(['audit secret-not-json', 'audit null', 'audit {}', line(event())], {}, x => output.push(x)), 3);
  assert.equal(output.length, 1);
  assert.equal(await review([], {}, () => assert.fail()), 0);
});
test('arguments require a file and valid UTC dates', () => {
  for (const args of [[], ['x', '--unknown'], ['x', '--run'], ['x', '--since', 'yesterday'],
    ['x', '--since', '2026-10-08T12:00:00-04:00'], ['x', '--since', '2026-10-09T12:00:00Z', '--until', '2026-10-08T12:00:00Z']]) {
    assert.throws(() => options(args));
  }
});
test('CLI exits nonzero and reports safe count for a malformed capture', () => {
  const directory = mkdtempSync(join(tmpdir(), 'synthetic-audit-'));
  try {
    const file = join(directory, 'capture.log');
    writeFileSync(file, 'audit SYNTHETIC_SECRET\n' + line(event()) + '\n');
    const result = spawnSync(process.execPath, ['scripts/audit-reader.mjs', file], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.equal(result.stderr, 'Malformed audit lines: 1\n');
    assert.deepEqual(JSON.parse(result.stdout), event());
    assert.ok(!result.stderr.includes('SYNTHETIC_SECRET'));
  } finally { rmSync(directory, { recursive: true }); }
});

test('inclusive nanosecond boundaries and invalid calendar dates', async () => {
  const instant = '2026-10-08T12:00:00.123456789Z';
  const filters = options(['capture.log', '--since', instant, '--until', instant]);
  const output = [];
  assert.equal(await review([line(event('run-one', 'run.completed', instant)),
    line(event('run-one', 'run.completed', '2026-10-08T12:00:00.123456788Z')),
    line(event('run-one', 'run.completed', '2026-10-08T12:00:00.123456790Z'))], filters, x => output.push(x)), 0);
  assert.equal(output.length, 1);
  assert.throws(() => options(['x', '--since', '2026-02-30T12:00:00Z']));
});
