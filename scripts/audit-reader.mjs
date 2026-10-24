#!/usr/bin/env node
// Read a caller-supplied capture only; never contact the server or write files.
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { readFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

// Preserve Java Instant nanoseconds when applying inclusive boundaries.
export function utcInstant(value) {
  if (typeof value !== 'string') throw new Error('UTC timestamp required');
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!match) throw new Error('UTC timestamp required');
  const millis = Date.parse(match[1] + 'Z');
  if (!Number.isFinite(millis) || new Date(millis).toISOString().slice(0, 19) !== match[1]) throw new Error('UTC timestamp required');
  return BigInt(millis) * 1_000_000n + BigInt((match[2] ?? '').padEnd(9, '0'));
}

export function options(args) {
  const result = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (['--run', '--action', '--since', '--until'].includes(arg)) {
      if (!args[i + 1] || args[i + 1].startsWith('--') || result[arg.slice(2)] !== undefined) throw new Error('Invalid arguments');
      result[arg.slice(2)] = args[++i];
    } else if (arg === '--verify') {
      if (result.verify) throw new Error('Invalid arguments');
      result.verify = true;
    } else if (arg.startsWith('--') || result.file) throw new Error('Invalid arguments');
    else result.file = arg;
  }
  if (!result.file) throw new Error('Captured log file required');
  for (const key of ['since', 'until']) {
    if (result[key] !== undefined) {
      result[key] = utcInstant(result[key]);
    }
  }
  if (result.since > result.until) throw new Error('Invalid time range');
  return result;
}

// The app's constant warnings after a lost event or journal. They carry no event, so they are counted apart
// from malformed lines and leave the exit status alone: the capture is complete, and the gap is in the app.
const GAP_WARNINGS = [
  'Audit event write failed; audit trail has a gap',
  'Audit journal unavailable; durable audit trail is not being written',
];

export async function review(lines, filters, output, onGap = () => {}) {
  let malformed = 0;
  for await (const line of lines) {
    // A log capture carries the `audit ` marker at the start of the logged message; a journal segment is bare JSON.
    const marker = line.startsWith('{') ? { index: 0, 0: '' } : /(?:^|:\s)audit /.exec(line);
    if (!marker) {
      // A gap warning is the whole logged message after the logger's separator.
      if (GAP_WARNINGS.some(warning => line.endsWith(': ' + warning))) onGap();
      continue;
    }
    let event;
    let time;
    try {
      event = JSON.parse(line.slice(marker.index + marker[0].length));
      if (!event || event.schemaVersion !== 1 || typeof event.eventId !== 'string' ||
          typeof event.action !== 'string' || typeof event.occurredAt !== 'string' ||
          !event.occurredAt.endsWith('Z')) throw new Error('Invalid event');
      time = utcInstant(event.occurredAt);
    } catch { malformed++; continue; }
    if (filters.run && event.runId !== filters.run) continue;
    if (filters.action && event.action !== filters.action) continue;
    if (filters.since !== undefined && time < filters.since) continue;
    if (filters.until !== undefined && time > filters.until) continue;
    output(JSON.stringify(event));
  }
  return malformed;
}

const SEGMENT = /^audit-\d{6}\.jsonl$/;
const SHA256 = /^[0-9a-f]{64}$/;

async function loadManifest(dir) {
  const manifest = JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8'));
  if (manifest?.version !== 1 || !Array.isArray(manifest.segments)) throw new Error('Unsupported manifest');
  for (const s of manifest.segments) {
    if (typeof s.file !== 'string' || !SEGMENT.test(s.file) || !SHA256.test(s.sha256)) throw new Error('Invalid manifest');
  }
  return manifest;
}

// Segment files in order: everything the manifest lists, then files it does not (open or crashed).
async function journalSegments(dir, manifest) {
  const listed = manifest.segments.map(s => s.file);
  const present = (await readdir(dir)).filter(n => SEGMENT.test(n));
  return [...new Set([...listed, ...present])].sort();
}

// The SHA-256 of a file's raw bytes and its last byte. Chunks keep memory bounded however large the segment is.
async function digest(path) {
  const hash = createHash('sha256');
  let last = null;
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk);
    if (chunk.length) last = chunk[chunk.length - 1];
  }
  return { sha256: hash.digest('hex'), last };
}

// Checksums catch accidental damage and missing or truncated files, not a rewrite by the machine owner.
// Output names segments and statuses only, never event content.
export async function verify(dir, write) {
  const manifest = await loadManifest(dir);
  const listed = new Map(manifest.segments.map(s => [s.file, s]));
  let problems = 0;
  for (const file of await journalSegments(dir, manifest)) {
    const entry = listed.get(file);
    let status = 'ok';
    if (!entry) status = 'unsealed';
    else {
      const path = join(dir, file);
      let sealed = null;
      try { sealed = await digest(path); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (sealed === null) status = 'missing';
      else if (sealed.sha256 !== entry.sha256) status = 'checksum_mismatch';
      else if (sealed.last !== null && sealed.last !== 0x0a) status = 'truncated';
      else {
        let events = 0;
        for await (const line of fileLines(path)) {
          if (!line) continue;
          try { if (JSON.parse(line).eventId) events++; else status = 'malformed'; } catch { status = 'malformed'; }
        }
        if (status === 'ok' && events !== entry.events) status = 'event_count_mismatch';
      }
    }
    if (status !== 'ok' && status !== 'unsealed') problems++;
    write(JSON.stringify({ segment: file.replace(/\.jsonl$/, ''), status }));
  }
  return problems;
}

// A line past MAX_LINE characters keeps only its first MAX_LINE characters, then TRUNCATED. Node cannot hold a string
// past about 512 MiB, and a segment can be larger than that. TRUNCATED is not JSON whitespace, so a cut line never
// parses as an event: an event line too long to hold counts as malformed.
const MAX_LINE = 16 * 1024 * 1024;
const TRUNCATED = '\u0000';

// The lines of a file, read in chunks so memory stays bounded however long the file is. Journal segments end lines with
// \n only. A capture log is split like readline: \n, \r and \r\n each end a line, even when \r\n spans two chunks.
async function* fileLines(path, capture = false) {
  const ends = capture ? /\r\n|\r|\n/ : '\n';
  let text = '';
  let cut = false;
  let afterCR = false;
  for await (let chunk of createReadStream(path, { encoding: 'utf8' })) {
    if (afterCR && chunk.startsWith('\n')) chunk = chunk.slice(1);
    afterCR = capture && chunk.endsWith('\r');
    const parts = chunk.split(ends);
    for (let i = 0; i < parts.length; i++) {
      if (i > 0) {
        yield lineText(text, cut);
        text = '';
        cut = false;
      }
      const room = MAX_LINE - text.length;
      if (parts[i].length > room) cut = true;
      text += parts[i].slice(0, room);
    }
  }
  yield lineText(text, cut);
}

// A segment line keeps no trailing carriage return, as JSON.parse ignored it before.
function lineText(text, cut) {
  if (cut) return text + TRUNCATED;
  return text.endsWith('\r') ? text.slice(0, -1) : text;
}

// Only a missing segment is skipped, because --verify reports it as `missing`. Any other read error ends the review.
async function* journalLines(dir) {
  const manifest = await loadManifest(dir);
  for (const file of await journalSegments(dir, manifest)) {
    try { yield* fileLines(join(dir, file)); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

async function main() {
  try {
    const filters = options(process.argv.slice(2));
    const isDir = (await stat(filters.file)).isDirectory();
    if (filters.verify) {
      if (!isDir) throw new Error('Journal directory required');
      const problems = await verify(filters.file, line => process.stdout.write(line + '\n'));
      if (problems) {
        process.stderr.write(`Journal segments with problems: ${problems}\n`);
        process.exitCode = 1;
      }
      return;
    }
    const lines = isDir ? journalLines(filters.file) : fileLines(filters.file, true);
    let gaps = 0;
    const malformed = await review(lines, filters, line => process.stdout.write(line + '\n'), () => gaps++);
    if (malformed) {
      process.stderr.write(`Malformed audit lines: ${malformed}\n`);
      process.exitCode = 1;
    }
    if (gaps) process.stderr.write(`Audit gap warnings: ${gaps}\n`);
  } catch {
    process.stderr.write('Audit reader failed: check arguments and captured log file or journal directory\n');
    process.exitCode = 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
