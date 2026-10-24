import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readdirSync, copyFileSync, appendFileSync, readFileSync, mkdirSync, chmodSync, truncateSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
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

// The app's own warnings after a lost event: the logger's line for a constant message, not an event.
const GAP = 'Audit event write failed; audit trail has a gap';
const JOURNAL_GAP = 'Audit journal unavailable; durable audit trail is not being written';
const warning = message => '2026-10-23T06:00:00.000-04:00  WARN 1 --- [main] [] i.g.d.payerworkbench.app.AuditLog : ' + message;

test('the app\'s gap warnings are reported on stderr, not counted as malformed lines', () => {
  const directory = mkdtempSync(join(tmpdir(), 'audit-gap-'));
  try {
    const file = join(directory, 'capture.log');
    writeFileSync(file, [line(event()), warning(GAP), warning(JOURNAL_GAP), line(event('run-two'))].join('\n') + '\n');
    const result = cli(file);
    assert.equal(result.status, 0);
    assert.equal(result.stderr, 'Audit gap warnings: 2\n');
    assert.equal(result.stdout.trim().split('\n').length, 2);
  } finally { rmSync(directory, { recursive: true }); }
});

test('a real malformed line still exits nonzero beside a gap warning, without echo', () => {
  const directory = mkdtempSync(join(tmpdir(), 'audit-gap-'));
  try {
    const file = join(directory, 'capture.log');
    writeFileSync(file, [warning(GAP), 'INFO logger : audit SYNTHETIC_SECRET', line(event())].join('\n') + '\n');
    const result = cli(file);
    assert.equal(result.status, 1);
    assert.equal(result.stderr, 'Malformed audit lines: 1\nAudit gap warnings: 1\n');
    assert.ok(!result.stderr.includes('SYNTHETIC_SECRET'));
  } finally { rmSync(directory, { recursive: true }); }
});

test('a line with the audit marker is malformed even when its message is a gap warning', async () => {
  let gaps = 0;
  assert.equal(await review(['INFO logger : audit ' + GAP], {}, () => assert.fail('no event'), () => gaps++), 1);
  assert.equal(gaps, 0);
});

// Class check: a constant message the app logs that mentions an audit must never be read as an event line,
// so a new warning cannot make the reader report a damaged capture.
test('every constant audit message in the app and mock payers is read without a malformed count', async () => {
  const repo = fileURLToPath(new URL('../', import.meta.url));
  const messages = new Set();
  for (const module of ['workbench-app', 'mock-payers']) {
    const root = join(repo, module, 'src/main/java');
    for (const name of readdirSync(root, { recursive: true }).filter(n => n.endsWith('.java'))) {
      const source = readFileSync(join(root, name), 'utf8');
      for (const [, literal] of source.matchAll(/"((?:[^"\\\n]|\\.)*)"/g)) {
        if (/audit /i.test(literal) && !literal.startsWith('audit {')) messages.add(literal);
      }
    }
  }
  assert.ok(messages.has(GAP) && messages.has(JOURNAL_GAP), 'the scan finds both known gap warnings');
  for (const message of messages) {
    assert.equal(await review([warning(message)], {}, () => assert.fail('a log message is not an event')), 0, message);
  }
});

// A segment that exists but cannot be read fails the run in both modes. Only a missing segment is skipped.
const canChmod = process.platform !== 'win32' && process.getuid() !== 0;
const unreadable = [
  { fault: 'a directory named as a segment', make: file => { rmSync(file); mkdirSync(file); }, skip: false },
  { fault: 'a segment without read permission', make: file => chmodSync(file, 0o000), skip: !canChmod },
];
for (const { fault, make, skip } of unreadable) {
  // Class check: any read failure other than a missing file is an error, so a catch-all cannot skip a segment.
  test(`class check: ${fault} fails the review and verify, and is never reported as missing`, { skip }, () => {
    const dir = makeJournal();
    try {
      make(join(dir, 'audit-000002.jsonl'));
      const reviewed = cli(dir);
      assert.equal(reviewed.status, 1);
      assert.match(reviewed.stderr, /Audit reader failed/);
      const verified = cli(dir, '--verify');
      assert.equal(verified.status, 1);
      assert.ok(!verified.stdout.includes('"segment":"audit-000002","status":"missing"'));
    } finally { rmSync(dir, { recursive: true }); }
  });
}

// Node cannot hold a string past about 512 MiB, so a segment that large must stream. A sparse file needs Linux here.
test('a segment over the string limit streams: its events print and its sparse padding is not an event', { skip: process.platform !== 'linux' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-sparse-'));
  try {
    const segment = join(dir, 'audit-000001.jsonl');
    writeFileSync(segment, JSON.stringify(event()) + '\n');
    truncateSync(segment, 600_000_000);
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ version: 1, segments: [] }));
    for (const target of [dir, segment]) {
      const result = cli(target);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, JSON.stringify(event()) + '\n');
    }
  } finally { rmSync(dir, { recursive: true }); }
});

test('an event line too long to hold whole counts as malformed, never as the event read from its prefix', () => {
  const directory = mkdtempSync(join(tmpdir(), 'audit-long-'));
  try {
    const file = join(directory, 'capture.log');
    writeFileSync(file, line(event()) + ' '.repeat(17 * 1024 * 1024) + '\n');
    const result = cli(file);
    assert.equal(result.status, 1);
    assert.equal(result.stderr, 'Malformed audit lines: 1\n');
    assert.equal(result.stdout, '');
  } finally { rmSync(directory, { recursive: true }); }
});

test('a CRLF capture reads the same as an LF one, including its gap warnings', () => {
  const directory = mkdtempSync(join(tmpdir(), 'audit-crlf-'));
  try {
    const file = join(directory, 'capture.log');
    writeFileSync(file, [line(event()), warning(GAP)].join('\r\n') + '\r\n');
    const result = cli(file);
    assert.equal(result.status, 0);
    assert.equal(result.stderr, 'Audit gap warnings: 1\n');
    assert.deepEqual(result.stdout.trim().split('\n').map(JSON.parse), [event()]);
  } finally { rmSync(directory, { recursive: true }); }
});
test('a capture with lone carriage-return line ends reads like readline did, CRLF across a chunk edge included', () => {
  const directory = mkdtempSync(join(tmpdir(), 'audit-cr-'));
  try {
    const file = join(directory, 'capture.log');
    // The filler puts the \r of its CRLF on the last byte of the first 64 KiB read chunk and the \n on the next. The empty
    // line a split there would add is not an audit line, so this only proves the events on either side still read.
    writeFileSync(file, 'x'.repeat(64 * 1024 - 1) + '\r\n' + [line(event()), warning(GAP), line(event('run-two'))].join('\r') + '\r');
    const result = cli(file);
    assert.equal(result.stderr, 'Audit gap warnings: 1\n');
    assert.equal(result.status, 0);
    assert.deepEqual(result.stdout.trim().split('\n').map(JSON.parse), [event(), event('run-two')]);
  } finally { rmSync(directory, { recursive: true }); }
});
