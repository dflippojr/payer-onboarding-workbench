import { test as base, expect, type Page } from '@playwright/test';
import { spawn } from 'node:child_process';
import { readFile, access } from 'node:fs/promises';
import { once } from 'node:events';

export const test = base.extend<{ instance: void }>({
  page: async ({ page }, use) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    page.on('response', response => { if (response.status() >= 400) errors.push(response.status() + ' ' + response.url()); });
    await use(page);
    expect(errors, 'unexpected browser/HTTP errors').toEqual([]);
  },
  baseURL: async ({ instance }, use) => {
    const state = JSON.parse(await readFile('.ui-test/instance.json', 'utf8'));
    if (!/^http:\/\/127[.]0[.]0[.]1:[0-9]+$/.test(state.baseURL)) throw new Error('Non-local test origin refused');
    await use(state.baseURL);
  },
  instance: [async ({}, use, testInfo) => {
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
        await expect.poll(async () => access(state.data).then(() => true, () => false)).toBe(false);
        await expect.poll(async () => access('.ui-test/instance.json').then(() => true, () => false)).toBe(false);
      }
      await testInfo.attach('synthetic-instance-log', { path: '.ui-test/app.log', contentType: 'text/plain' });
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
  await expect.poll(() => page.evaluate(() => {
    const dark = matchMedia('(prefers-color-scheme: dark)').matches;
    return getComputedStyle(document.documentElement).getPropertyValue('--paper').trim() === (dark ? '#151b18' : '#f6f3eb');
  })).toBe(true);
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
export async function auditEvent(action: string, id: string, metadata: Record<string, unknown> = {}) {
  await expect.poll(async () => {
    const text = await readFile('.ui-test/app.log', 'utf8');
    return text.split('\n').filter(line => line.includes(' : audit ')).map(line => {
      try { return JSON.parse(line.slice(line.indexOf(' : audit ') + 9)); } catch { return null; }
    }).some(event => event?.action === action && event.runId === id && event.actorType === 'anonymous'
      && event.source === 'http' && event.outcome === 'success'
      && Object.entries(metadata).every(([key, value]) => JSON.stringify(event.metadata[key]) === JSON.stringify(value)));
  }).toBe(true);
}

export async function audit(action: string, id: string, payer: string, environment = 'SANDBOX') {
  await auditEvent(action, id, { payerId: payer, environment, sampleId: 'order-sign-hospital-bed' });
}
