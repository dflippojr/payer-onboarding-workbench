// Thin wrapper over Playwright Test: drives the main path (or one feature) against the launched instance.
import { spawn } from 'node:child_process';
import { createWriteStream, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import { root } from './doctor.mjs';

export const FEATURES = ['healthy', 'failure', 'report', 'reset', 'running', 'compare'];
const TEST_ONLY = ['selftest-fail'];

/** Resolves to the exit code. onSpawn receives the PID before any test runs, so it can be recorded. */
export async function drive({ evidenceDir, feature, onSpawn = () => {} }) {
  if (feature && !FEATURES.includes(feature) && !TEST_ONLY.includes(feature)) {
    throw new Error('Unknown feature ' + feature + '; choose one of ' + FEATURES.join(', '));
  }
  if (!existsSync(join(root, '.ui-test', 'instance.json'))) throw new Error('Launch the instance first');
  const filter = feature ? ['--grep', '@' + feature + '\\b'] : ['--grep-invert', '@selftest'];
  const cli = join(root, 'node_modules', '@playwright', 'test', 'cli.js');
  const child = spawn(process.execPath, [cli, 'test', '-c', '.claude/skills/verify/drive/playwright.config.ts',
    '--workers=1', ...filter], {
    cwd: root, env: { ...process.env, VERIFY_EVIDENCE: resolve(evidenceDir) },
    stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, detached: process.platform !== 'win32',
  });
  onSpawn(child.pid);
  const log = createWriteStream(join(evidenceDir, 'drive.log'));
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { log.write(chunk); process.stdout.write(chunk); });
  const [code] = await once(child, 'exit');
  log.end();
  return code ?? 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [evidenceDir, feature] = process.argv.slice(2);
  if (!evidenceDir) throw new Error('Usage: node .claude/skills/verify/scripts/drive.mjs <evidence-dir> [feature]');
  process.exitCode = await drive({ evidenceDir, feature });
}
