// Cleanup for one verification run: the contract teardown (docs/ui-testing.md "Teardown"), then
// every process recorded in <evidence>/launch.json, by recorded PID only. Safe to run repeatedly.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { handlePath, listening, root } from './doctor.mjs';

const windows = process.platform === 'win32';

export function alive(pid) {
  if (!Number.isInteger(pid)) return false;
  try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; }
}

/** Stops a recorded process and its children. POSIX children were spawned as group leaders. */
function killTree(pid, group) {
  if (windows) spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true });
  else try { process.kill(group ? -pid : pid, 'SIGKILL'); } catch { /* already gone */ }
}

async function until(predicate, timeoutMs) {
  for (let waited = 0; waited < timeoutMs; waited += 200) {
    if (await predicate()) return true;
    await delay(200);
  }
  return predicate();
}

function teardown() {
  const result = spawnSync(process.execPath, ['scripts/ui-instance.mjs', 'stop'], { cwd: root, encoding: 'utf8', windowsHide: true });
  return { ok: result.status === 0, output: (result.stdout + result.stderr).trim() };
}

/** Returns { ok, checks } and writes cleanup.json into the evidence folder. */
export async function cleanup(evidenceDir) {
  const launchFile = resolve(evidenceDir, 'launch.json');
  const launch = existsSync(launchFile) ? JSON.parse(readFileSync(launchFile, 'utf8')) : {};
  const checks = [];
  const check = (name, ok, detail) => checks.push({ name, ok: Boolean(ok), detail });

  // The handle is ours only if this run created it (launch.json records that no handle existed before).
  const owned = launch.ownsHandle === true;
  if (owned) {
    const stopped = teardown();
    check('contract-teardown', stopped.ok, stopped.output || 'node scripts/ui-instance.mjs stop');
  } else {
    check('contract-teardown', true, 'skipped: this run did not start an instance');
  }

  // Anything still running after the teardown was started by this run: stop it by recorded PID.
  const pids = Object.entries(launch.pids ?? {});
  for (const [role, pid] of pids) {
    if (!alive(pid)) continue;
    // Drive and launcher are our direct children (POSIX group leaders); the supervisor is detached by the launcher.
    killTree(pid, role !== 'java');
    await until(() => !alive(pid), 10_000);
  }
  for (const [role, pid] of pids) check('pid-' + role, !alive(pid), pid + (alive(pid) ? ' still running' : ' exited'));

  // A killed supervisor cannot remove its own data: repeat the launcher's guarded removal.
  if (owned && launch.data && existsSync(launch.data)) {
    const base = resolve(launch.data);
    const guard = /[\\/]ui-workbench-[^\\/]+$/.test(base);
    if (guard) {
      await until(() => {
        spawnSync(windows ? 'powershell.exe' : 'rm', windows
          ? ['-NoProfile', '-NonInteractive', '-Command', "Remove-Item -LiteralPath '" + base.replaceAll("'", "''") + "' -Recurse -Force -ErrorAction SilentlyContinue"]
          : ['-rf', '--', base], { windowsHide: true });
        return !existsSync(base);
      }, 10_000);
    }
  }
  if (owned && existsSync(handlePath)) {
    const handle = JSON.parse(readFileSync(handlePath, 'utf8'));
    // Only our own handle, and only once its supervisor is gone: a live one is left for the error report.
    if (handle.supervisorPid === launch.pids?.supervisor && !alive(handle.supervisorPid)) unlinkSync(handlePath);
  }

  check('handle-removed', !owned || !existsSync(handlePath), '.ui-test/instance.json ' + (existsSync(handlePath) ? 'remains' : 'absent'));
  check('data-removed', !launch.data || !existsSync(launch.data), (launch.data ?? 'no data dir recorded') + (launch.data && existsSync(launch.data) ? ' remains' : ''));
  for (const [name, port] of Object.entries({ app: launch.port, control: launch.controlPort })) {
    if (!port) continue;
    const free = await until(async () => !(await listening('127.0.0.1', port)), 10_000);
    check('port-' + name, free, '127.0.0.1:' + port + (free ? ' free' : ' still listening'));
  }
  const ok = checks.every(c => c.ok);
  writeFileSync(resolve(evidenceDir, 'cleanup.json'), JSON.stringify({ ok, checks }, null, 2));
  return { ok, checks };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error('Usage: node .claude/skills/verify/scripts/cleanup.mjs <evidence-dir>');
  const result = await cleanup(process.argv[2]);
  for (const c of result.checks) console.log((c.ok ? 'PASS ' : 'FAIL ') + c.name.padEnd(20) + c.detail);
  process.exitCode = result.ok ? 0 : 1;
}
