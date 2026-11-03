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
import { alive, cleanup } from './cleanup.mjs';
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
function spawnStub() {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { detached: true, stdio: 'ignore', windowsHide: true });
  child.unref();
  return child.pid;
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
    try { process.kill(-pid, 'SIGKILL'); } catch { /* gone */ }
    rmSync(dir, { recursive: true, force: true });
  }
});
