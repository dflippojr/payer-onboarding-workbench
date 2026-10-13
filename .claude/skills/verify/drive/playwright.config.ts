import { defineConfig, devices } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Drives the instance the verify skill already launched; it never starts its own server.
const state = JSON.parse(readFileSync('.ui-test/instance.json', 'utf8'));
if (!/^http:\/\/127[.]0[.]0[.]1:[0-9]+$/.test(state.baseURL)) throw new Error('Non-local verify origin refused');
const evidence = process.env.VERIFY_EVIDENCE;
if (!evidence) throw new Error('Run through .claude/skills/verify/scripts/drive.mjs');

export default defineConfig({
  testDir: '.',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  outputDir: join(evidence, 'playwright'),
  reporter: [['list']],
  use: { baseURL: state.baseURL, actionTimeout: 15_000, trace: 'retain-on-failure', screenshot: 'only-on-failure' },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } },
    { name: 'phone', use: { ...devices['iPhone SE'] } },
  ],
});
