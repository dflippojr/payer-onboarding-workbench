import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readdirSync, copyFileSync, appendFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
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

test('selects admin fault and lifecycle events from the synthetic fixture', async () => {
  const { createReadStream } = await import('node:fs');
  const { createInterface } = await import('node:readline');
  for (const [action, outcome] of [['fault.enable', 'success'], ['cleanup.finished', 'partial']]) {
    const output = [];
    const lines = createInterface({ input: createReadStream('scripts/fixtures/audit-synthetic.jsonl') });
    assert.equal(await review(lines, options(['x', '--action', action]), x => output.push(x)), 0);
    assert.deepEqual(output.map(x => JSON.parse(x).outcome), [outcome]);
  }
});

// Journal directory: bare JSON-lines segments plus a manifest with SHA-256 checksums.
const SECRET = 'SYNTHETIC_CLIENT_SECRET_MARKER';
function makeJournal() {
  const dir = mkdtempSync(join(tmpdir(), 'audit-journal-'));
  const segments = [];
  const files = [[event('run-a', 'run.requested', '2026-10-08T12:00:00Z'), event('run-b', 'run.completed', '2026-10-08T12:00:01Z')],
    [event('run-a', 'report.rendered', '2026-10-08T12:00:02Z')]];
  files.forEach((events, i) => {
    const name = `audit-00000${i + 1}.jsonl`;
    const text = events.map(e => JSON.stringify({ ...e, eventId: `id-${i}-${e.runId}`, note: SECRET })).join('\n') + '\n';
    writeFileSync(join(dir, name), text);
    segments.push({ id: name.replace('.jsonl', ''), file: name, bytes: Buffer.byteLength(text), events: events.length,
      sha256: createHash('sha256').update(text).digest('hex') });
  });
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ version: 1, operatorLabel: null, segments }));
  return dir;
}
const cli = (...args) => spawnSync(process.execPath, [new URL('./audit-reader.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'), ...args],
  { encoding: 'utf8' });

test('journal directory review filters across segments and a restored copy reads the same events', () => {
  const dir = makeJournal();
  const restored = mkdtempSync(join(tmpdir(), 'audit-restored-'));
  try {
    const all = cli(dir);
    assert.equal(all.status, 0);
    assert.equal(all.stdout.trim().split('\n').length, 3);
    assert.equal(cli(dir, '--run', 'run-a').stdout.trim().split('\n').length, 2);
    for (const f of readdirSync(dir)) copyFileSync(join(dir, f), join(restored, f));
    assert.equal(cli(restored).stdout, all.stdout);
  } finally { rmSync(dir, { recursive: true }); rmSync(restored, { recursive: true }); }
});

test('verify passes a clean journal and reports damage by segment without echoing content', () => {
  const dir = makeJournal();
  try {
    const ok = cli(dir, '--verify');
    assert.equal(ok.status, 0);
    assert.deepEqual(ok.stdout.trim().split('\n').map(JSON.parse).map(r => r.status), ['ok', 'ok']);

    appendFileSync(join(dir, 'audit-000002.jsonl'), `{"truncated":"${SECRET}`);
    let bad = cli(dir, '--verify');
    assert.equal(bad.status, 1);
    assert.match(bad.stdout, /"segment":"audit-000002","status":"checksum_mismatch"/);

    rmSync(join(dir, 'audit-000001.jsonl'));
    writeFileSync(join(dir, 'audit-000009.jsonl'), '');
    bad = cli(dir, '--verify');
    assert.match(bad.stdout, /"segment":"audit-000001","status":"missing"/);
    assert.match(bad.stdout, /"segment":"audit-000009","status":"unsealed"/);
    assert.ok(!bad.stdout.includes(SECRET) && !bad.stderr.includes(SECRET));
    const read = cli(dir);
    assert.equal(read.status, 1, 'a damaged line makes the review nonzero');
    assert.ok(!read.stderr.includes(SECRET));
  } finally { rmSync(dir, { recursive: true }); }
});

test('verify rejects a manifest that names other files and a non-directory', () => {
  const dir = makeJournal();
  try {
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ version: 1, segments: [{ file: '../x', sha256: 'a'.repeat(64) }] }));
    assert.equal(cli(dir, '--verify').status, 1);
    assert.equal(cli(join(dir, 'audit-000001.jsonl'), '--verify').status, 1);
  } finally { rmSync(dir, { recursive: true }); }
});
