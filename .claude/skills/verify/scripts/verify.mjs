// Launch -> doctor -> drive -> evidence -> cleanup. Cleanup always runs, even after a failed step.
// Usage: node .claude/skills/verify/scripts/verify.mjs [--feature <name>]
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { cleanup } from './cleanup.mjs';
import { format, handlePath, root, runDoctor } from './doctor.mjs';
import { drive, FEATURES } from './drive.mjs';

const args = process.argv.slice(2);
const flag = args.findIndex(arg => arg === '--feature' || arg.startsWith('--feature='));
const feature = flag < 0 ? undefined : args[flag].includes('=') ? args[flag].split('=')[1] : args[flag + 1];
if (args.length > (flag < 0 ? 0 : args[flag].includes('=') ? 1 : 2) || (flag >= 0 && !feature)) {
  throw new Error('Usage: verify.mjs [--feature ' + FEATURES.join('|') + ']');
}

const evidenceDir = join(root, '.verify', new Date().toISOString().replace(/[:.]/g, '-'));
mkdirSync(evidenceDir, { recursive: true });
const launch = { startedAt: new Date().toISOString(), feature: feature ?? 'all', ownsHandle: false, pids: {} };
const save = () => writeFileSync(join(evidenceDir, 'launch.json'), JSON.stringify(launch, null, 2));
const steps = [];
const step = (name, ok, detail) => { steps.push({ name, ok, detail }); console.log((ok ? 'PASS ' : 'FAIL ') + name + ': ' + detail); };
save();

async function launchInstance() {
  if (existsSync(handlePath)) throw new Error('This worktree already has an instance; it is not ours to stop (see docs/ui-testing.md "Teardown")');
  launch.ownsHandle = true;
  const child = spawn(process.execPath, ['scripts/ui-instance.mjs', 'start'], {
    cwd: root, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, detached: process.platform !== 'win32',
  });
  launch.pids.launcher = child.pid;
  save();
  let output = '';
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { output += chunk; });
  const [code] = await once(child, 'exit');
  writeFileSync(join(evidenceDir, 'launch.log'), output);
  if (existsSync(handlePath)) {
    const state = JSON.parse(readFileSync(handlePath, 'utf8'));
    Object.assign(launch.pids, { supervisor: state.supervisorPid, ...(state.pid ? { java: state.pid } : {}) });
    Object.assign(launch, {
      baseURL: state.baseURL, port: Number(state.baseURL?.split(':')[2]) || undefined,
      controlPort: Number(state.control.split(':')[2]), data: state.data, appLog: state.log,
      supervisorLog: join(root, '.ui-test', 'supervisor.log'),
    });
    save();
  }
  if (code !== 0 || !output.includes('UI_TEST_URL=')) throw new Error('Launch failed (exit ' + code + '); see launch.log and .ui-test/supervisor.log');
  step('launch', true, launch.baseURL + ' java=' + launch.pids.java + ' supervisor=' + launch.pids.supervisor);
}

function logExcerpts() {
  const keep = /Started WorkbenchApplication|started on port| : audit | ERROR | WARN |Exception/;
  const parts = [];
  for (const file of [launch.appLog, launch.supervisorLog]) {
    if (!file || !existsSync(file)) continue;
    const lines = readFileSync(file, 'utf8').split('\n');
    const picked = file === launch.appLog ? lines.filter(line => keep.test(line)).slice(-200) : lines.slice(-50);
    parts.push('== ' + relative(root, file) + ' (' + picked.length + ' of ' + lines.length + ' lines)\n' + picked.join('\n'));
  }
  writeFileSync(join(evidenceDir, 'logs.txt'), parts.join('\n\n') + '\n');
}

function summary(cleanupResult, error) {
  const commit = spawnSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: root, encoding: 'utf8' }).stdout.trim();
  const dirty = spawnSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).stdout.trim() ? ' (uncommitted changes)' : '';
  const shots = existsSync(join(evidenceDir, 'screenshots')) ? readdirSync(join(evidenceDir, 'screenshots')) : [];
  const driveLog = existsSync(join(evidenceDir, 'drive.log')) ? readFileSync(join(evidenceDir, 'drive.log'), 'utf8') : '';
  const tally = driveLog.split('\n').filter(line => /^\s+\d+ (passed|failed|flaky|skipped|did not run)/.test(line)).map(s => s.trim());
  const doctor = existsSync(join(evidenceDir, 'doctor.txt')) ? readFileSync(join(evidenceDir, 'doctor.txt'), 'utf8').trim() : 'not run';
  const ok = !error && steps.every(s => s.ok);
  return [
    '# Verification summary', '',
    '- Result: **' + (ok ? 'PASS' : 'FAIL') + '**' + (error ? ' (' + error + ')' : ''),
    '- Commit: ' + commit + dirty,
    '- Feature: ' + launch.feature,
    '- Instance: ' + (launch.baseURL ?? 'not started') + ', java PID ' + (launch.pids.java ?? '-') + ', supervisor PID ' + (launch.pids.supervisor ?? '-'),
    '- Started: ' + launch.startedAt, '',
    '| Step | Result | Detail |', '| --- | --- | --- |',
    ...steps.map(s => '| ' + s.name + ' | ' + (s.ok ? 'PASS' : 'FAIL') + ' | ' + String(s.detail).replaceAll('|', '/') + ' |'), '',
    '## Doctor', '', '```text', doctor, '```', '',
    '## Drive', '', tally.length ? tally.map(t => '- ' + t).join('\n') : '- not run', '',
    '## Screenshots', '', shots.length ? shots.map(s => '- screenshots/' + s).join('\n') : '- none', '',
    '## Cleanup', '', ...(cleanupResult?.checks ?? []).map(c => '- ' + (c.ok ? 'PASS ' : 'FAIL ') + c.name + ': ' + c.detail), '',
    'Files: launch.json, launch.log, doctor.txt, drive.log, logs.txt, cleanup.json, screenshots/, reports/.', '',
  ].join('\n');
}

let error;
let cleanupResult;
try {
  await launchInstance();
  const checks = await runDoctor({ expectedPort: launch.port });
  writeFileSync(join(evidenceDir, 'doctor.txt'), format(checks) + '\n');
  const doctorOk = checks.every(c => c.ok);
  step('doctor', doctorOk, checks.filter(c => c.ok).length + '/' + checks.length + ' checks pass');
  if (!doctorOk) throw new Error('Doctor failed; drive skipped');
  const code = await drive({ evidenceDir, feature, onSpawn: pid => { launch.pids.drive = pid; save(); } });
  step('drive', code === 0, (feature ?? 'all features') + ', exit ' + code);
} catch (caught) {
  error = caught.message;
  console.error(error);
} finally {
  try { cleanupResult = await cleanup(evidenceDir); }
  catch (caught) { cleanupResult = { ok: false, checks: [{ name: 'cleanup', ok: false, detail: caught.message }] }; }
  step('cleanup', cleanupResult.ok, cleanupResult.checks.filter(c => c.ok).length + '/' + cleanupResult.checks.length + ' checks pass');
  logExcerpts();
  step('evidence', true, relative(root, evidenceDir));
  writeFileSync(join(evidenceDir, 'summary.md'), summary(cleanupResult, error));
  console.log('VERIFY_EVIDENCE=' + evidenceDir);
  process.exitCode = !error && steps.every(s => s.ok) ? 0 : 1;
}
