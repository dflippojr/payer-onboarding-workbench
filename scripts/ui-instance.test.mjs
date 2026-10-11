import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const run = promisify(execFile);
const dataDirs = () => readdirSync(tmpdir()).filter(name => name.startsWith('ui-workbench-')).sort();

test('refuses external configuration and Java option injection before creating an instance', async () => {
  assert.equal(existsSync('.ui-test/instance.json'), false, 'stop the owned instance before these tests');
  const before = dataDirs();
  for (const key of ['SPRING_CONFIG_IMPORT', 'WORKBENCH_CUSTOM_ENDPOINTS_ENABLED', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS']) {
    await assert.rejects(run(process.execPath, ['scripts/ui-instance.mjs', 'serve'], {
      env: { ...process.env, [key]: 'synthetic-refusal-probe' }, windowsHide: true,
    }), error => error.stderr.includes('Remove configuration overrides') && !error.stderr.includes('synthetic-refusal-probe'));
    assert.equal(existsSync('.ui-test/instance.json'), false);
  }
  assert.deepEqual(dataDirs(), before);
});

test('refuses endpoint/credential arguments and cleans up a partial Java launch failure', async () => {
  const before = dataDirs();
  await assert.rejects(run(process.execPath, ['scripts/ui-instance.mjs', 'start', '--endpoint=https://payer.invalid'],
    { windowsHide: true }), error => error.stderr.includes('Usage:'));
  await assert.rejects(run(process.execPath, ['scripts/ui-instance.mjs', 'serve'], {
    env: { ...process.env, JAVA_HOME: join(tmpdir(), 'ui-no-such-jdk') }, windowsHide: true,
  }), error => error.stderr.includes('ENOENT'));
  assert.equal(existsSync('.ui-test/instance.json'), false);
  assert.deepEqual(dataDirs(), before);
  await run(process.execPath, ['scripts/ui-instance.mjs', 'stop'], { windowsHide: true });
  await run(process.execPath, ['scripts/ui-instance.mjs', 'stop'], { windowsHide: true });
});
