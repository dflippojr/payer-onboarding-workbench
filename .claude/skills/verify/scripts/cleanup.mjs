// Cleanup for one verification run: the contract teardown (docs/ui-testing.md "Teardown"), then
// every process recorded in <evidence>/launch.json, by recorded PID only. Safe to run repeatedly:
// a PID is killed only while its start time and command line still match the identity launch.json
// recorded for it, so an old evidence folder cannot kill an unrelated process that reused the PID.
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

/**
 * Returns a string that identifies the process now holding pid (its start time and command line), or
 * null when no such process can be read. Two processes that share a PID over time get different values.
 */
export function identify(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  if (process.platform === 'linux') {
    try {
      // Field 22 of /proc/<pid>/stat is the start time in clock ticks since boot; the command name
      // (field 2) can hold spaces and parentheses, so count fields from the last ')'.
      const stat = readFileSync('/proc/' + pid + '/stat', 'utf8');
      const start = stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19];
      const cmd = readFileSync('/proc/' + pid + '/cmdline', 'utf8').replaceAll('\0', ' ').trim();
      return start ? 'start=' + start + ' cmd=' + cmd : null;
    } catch { return null; }
  }
  const result = windows
    ? spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      '$p = Get-CimInstance Win32_Process -Filter "ProcessId=' + pid + '"; if ($p) { "start=" + $p.CreationDate.ToUniversalTime().ToString("o") + " cmd=" + $p.CommandLine }'],
    { encoding: 'utf8', windowsHide: true })
    : spawnSync('ps', ['-o', 'lstart=', '-o', 'args=', '-p', String(pid)], { encoding: 'utf8', env: { ...process.env, LC_ALL: 'C' } });
  const out = (result.stdout ?? '').trim();
  if (result.status !== 0 || !out) return null;
  // lstart is a fixed 24-character date (e.g. "Thu Jan  1 00:00:00 1970"); args follows it.
  return windows ? out : 'start=' + out.slice(0, 24) + ' cmd=' + out.slice(24).trim();
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

  // Anything still running after the teardown was started by this run: stop it by recorded PID, but
  // only while the PID still names the recorded process. A mismatch means the PID was reused: skip it.
  const pids = Object.entries(launch.pids ?? {});
  const skipped = new Map();
  for (const [role, pid] of pids) {
    if (!alive(pid)) continue;
    const recorded = launch.identities?.[role];
    const current = identify(pid);
    if (!recorded || current !== recorded) {
      skipped.set(role, recorded
        ? 'skipped: ' + pid + ' is alive but does not match the recorded process (recorded "' + recorded + '", now "' + current + '")'
        : 'skipped: ' + pid + ' is alive but launch.json recorded no identity for it, so it may not be ours');
      continue;
    }
    // Drive and launcher are our direct children (POSIX group leaders); the supervisor is detached by the launcher.
    killTree(pid, role !== 'java');
    await until(() => !alive(pid), 10_000);
  }
  for (const [role, pid] of pids) {
    if (skipped.has(role)) check('pid-' + role, true, skipped.get(role));
    else check('pid-' + role, !alive(pid), pid + (alive(pid) ? ' still running' : ' exited'));
  }
  for (const detail of skipped.values()) console.warn('cleanup: ' + detail);

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
