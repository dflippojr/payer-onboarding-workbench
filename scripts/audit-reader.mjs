#!/usr/bin/env node
// Read a caller-supplied capture only; never contact the server or write files.
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
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

export async function review(lines, filters, output) {
  let malformed = 0;
  for await (const line of lines) {
    const marker = /(?:^|\s)audit /.exec(line);
    if (!marker) continue;
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

async function main() {
  try {
    const filters = options(process.argv.slice(2));
    const lines = createInterface({ input: createReadStream(filters.file), crlfDelay: Infinity });
    const malformed = await review(lines, filters, line => process.stdout.write(line + '\n'));
    if (malformed) {
      process.stderr.write(`Malformed audit lines: ${malformed}\n`);
      process.exitCode = 1;
    }
  } catch {
    process.stderr.write('Audit reader failed: check arguments and captured log file\n');
    process.exitCode = 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
