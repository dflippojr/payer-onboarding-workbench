import { test as base, expect, type Page } from '@playwright/test';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';

export const test = base.extend<{ instance: void }>({
  baseURL: async ({ instance }, use) => {
    const state = JSON.parse(await readFile('.ui-test/instance.json', 'utf8'));
    if (!/^http:\/\/127[.]0[.]0[.]1:[0-9]+$/.test(state.baseURL)) throw new Error('Non-local test origin refused');
    await use(state.baseURL);
  },
  instance: [async ({}, use) => {
    const child = spawn(process.execPath, ['scripts/ui-instance.mjs', 'serve'], { windowsHide: true });
    let output = '';
    const ready = new Promise<void>((resolve, reject) => {
      child.stdout.on('data', chunk => { output += chunk; if (output.includes('UI_TEST_URL=')) resolve(); });
      child.stderr.on('data', chunk => { output += chunk; });
      child.once('error', reject);
      child.once('exit', code => reject(new Error('Instance exited: ' + code + '\n' + output)));
    });
    try { await ready; await use(); }
    finally {
      if (child.exitCode === null && child.signalCode === null) {
        const state = JSON.parse(await readFile('.ui-test/instance.json', 'utf8'));
        const exited = once(child, 'exit');
        const response = await fetch(state.control + '/stop', { method: 'POST', headers: { 'X-Instance': state.token } });
        if (!response.ok) throw new Error('Instance cleanup refused');
        await exited;
      }
    }
  }, { auto: true, timeout: 150_000 }],
});
export { expect };

export async function ready(page: Page) {
  await page.goto('/');
  await expect(page.getByRole('radio')).toHaveCount(3);
  await expect(page.locator('#sample option')).toHaveCount(6);
  await expect(page.getByRole('button', { name: 'Run onboarding' })).toBeEnabled();
  await expect(page.locator('#recent-runs')).not.toContainText('Loading');
  await page.evaluate(() => document.fonts.ready);
}
export async function runOnboarding(page: Page) {
  const response = page.waitForResponse(r => r.url().endsWith('/api/runs') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Run onboarding' }).click();
  const result = await (await response).json();
  await expect(page.locator('#steps > li')).toHaveCount(6);
  await expect(page.locator('#run-status')).toContainText('Done:');
  await expect(page.getByLabel('Recent runs')).toHaveValue(result.runId);
  return result;
}
export async function reopen(page: Page, id: string) {
  await page.reload();
  await expect(page.locator('#recent-runs option[value="' + id + '"]')).toBeAttached();
  await page.getByLabel('Recent runs').selectOption(id);
  await expect(page.locator('#history-status')).toHaveText('Run reopened.');
  await expect(page.locator('#run-meta')).toContainText(id);
}
export async function audit(action: string, id: string, payer: string, environment = 'SANDBOX') {
  await expect.poll(async () => {
    const text = await readFile('.ui-test/app.log', 'utf8');
    return text.split('\n').filter(line => line.includes(' : audit ')).map(line => {
      try { return JSON.parse(line.slice(line.indexOf(' : audit ') + 9)); } catch { return null; }
    }).some(event => event?.action === action && event.runId === id && event.actorType === 'anonymous'
      && event.source === 'http' && event.outcome === 'success' && event.metadata.payerId === payer
      && event.metadata.environment === environment);
  }).toBe(true);
}
