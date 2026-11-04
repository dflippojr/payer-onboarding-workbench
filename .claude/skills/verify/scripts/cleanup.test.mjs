// Integration: a real launch whose drive step fails on purpose must still leave nothing behind
// (needs the built jar and Playwright browsers, docs/ui-testing.md "Scope and isolation"), and unit
// tests of the PID identity check that keeps cleanup from killing a process that reused a recorded PID.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { alive, cleanup, identify } from './cleanup.mjs';
import { handlePath, listening, root } from './doctor.mjs';

const run = promisify(execFile);
const built = existsSync(join(root, 'workbench-app', 'target'))
  && readdirSync(join(root, 'workbench-app', 'target')).some(name => /^workbench-app-.*\.jar$/.test(name));

test('cleanup succeeds after a deliberately failed drive step', { skip: !built && 'build the jar first', timeout: 300_000 }, async () => {
  assert.equal(existsSync(handlePath), false, 'stop the owned instance before this test');
  const failure = await run(process.execPath, ['.claude/skills/verify/scripts/verify.mjs', '--feature', 'selftest-fail'],
    { cwd: root, windowsHide: true, maxBuffer: 16 * 1024 * 1024 }).then(() => null, error => error);
  assert.ok(failure, 'verify must exit non-zero when drive fails');
  const evidence = failure.stdout.match(/VERIFY_EVIDENCE=(.+)/)[1].trim();
  const summary = readFileSync(join(evidence, 'summary.md'), 'utf8');
  assert.match(summary, /\| launch \| PASS/);
  assert.match(summary, /\| doctor \| PASS/);
  assert.match(summary, /\| drive \| FAIL/);
  assert.match(summary, /\| cleanup \| PASS/);

  const launch = JSON.parse(readFileSync(join(evidence, 'launch.json'), 'utf8'));
  for (const role of ['launcher', 'supervisor', 'java', 'drive']) {
    assert.ok(Number.isInteger(launch.pids[role]), role + ' PID recorded');
    assert.equal(alive(launch.pids[role]), false, role + ' still running');
  }
  assert.equal(existsSync(handlePath), false);
  assert.equal(existsSync(launch.data), false);
  assert.equal(await listening('127.0.0.1', launch.port), false);
  assert.equal(await listening('127.0.0.1', launch.controlPort), false);
  assert.ok(JSON.parse(readFileSync(join(evidence, 'cleanup.json'), 'utf8')).ok);
});

// A recorded PID can be reused by an unrelated process once the recorded one exits. A stub process stands
// in for that stranger: its PID is in launch.json, but the recorded identity belongs to someone else.
function spawnStub(tag = 'stub') {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)', tag], { detached: true, stdio: 'ignore', windowsHide: true });
  child.unref();
  return child.pid;
}

// Stubs have no children, so the plain PID is enough on every platform (Windows has no process groups).
async function stopStub(pid) {
  try { process.kill(pid, 'SIGKILL'); } catch { /* gone */ }
  for (let i = 0; i < 50 && alive(pid); i++) await new Promise(r => setTimeout(r, 100));
}

function writeLaunch(dir, launch) {
  writeFileSync(join(dir, 'launch.json'), JSON.stringify({ ownsHandle: false, ...launch }, null, 2));
}

test('cleanup skips a recorded PID that now belongs to a different process', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'verify-cleanup-'));
  const pid = spawnStub();
  try {
    writeLaunch(dir, { pids: { drive: pid }, identities: { drive: 'start=Thu Jan  1 00:00:00 1970 cmd=someone-else' } });
    const result = await cleanup(dir);
    assert.equal(alive(pid), true, 'a process that is not the recorded one must not be killed');
    const check = result.checks.find(c => c.name === 'pid-drive');
    assert.match(check.detail, /skipped/);
    assert.match(check.detail, /does not match/);
  } finally {
    await stopStub(pid);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('cleanup kills a recorded PID whose identity matches, and a second run is still safe', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'verify-cleanup-'));
  const pid = spawnStub();
  try {
    const identity = identify(pid);
    assert.match(identity, /^start=\S.* cmd=.*setInterval/);
    writeLaunch(dir, { pids: { drive: pid }, identities: { drive: identity } });
    const first = await cleanup(dir);
    assert.equal(alive(pid), false, 'the recorded process must be killed');
    assert.ok(first.ok);
    assert.equal(first.checks.find(c => c.name === 'pid-drive').detail, pid + ' exited');
    const second = await cleanup(dir);
    assert.ok(second.ok, 'a second run must succeed');
    assert.equal(second.checks.find(c => c.name === 'pid-drive').detail, pid + ' exited');
  } finally {
    await stopStub(pid);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('cleanup skips a live recorded PID when launch.json recorded no identity for it', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'verify-cleanup-'));
  const pid = spawnStub();
  try {
    writeLaunch(dir, { pids: { drive: pid } });
    const result = await cleanup(dir);
    assert.equal(alive(pid), true, 'an unidentified process must not be killed');
    assert.match(result.checks.find(c => c.name === 'pid-drive').detail, /skipped: .*recorded no identity/);
  } finally {
    await stopStub(pid);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('identify tells apart two processes and returns null for a PID that is gone', async () => {
  // Started in the same clock tick, two processes can share a start time; the command line still differs.
  const a = spawnStub('first');
  const b = spawnStub('second');
  try {
    assert.notEqual(identify(a), identify(b));
    assert.equal(identify(a), identify(a), 'the identity of one process is stable');
  } finally {
    for (const pid of [a, b]) await stopStub(pid);
  }
  assert.equal(alive(a), false);
  assert.equal(identify(a), null);
});
