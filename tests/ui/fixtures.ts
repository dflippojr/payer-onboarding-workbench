import { test as base, expect, type Page, type Request } from '@playwright/test';
import { spawn } from 'node:child_process';
import { readFile, access } from 'node:fs/promises';
import { once } from 'node:events';
import { loadavg } from 'node:os';

type Instance = { baseURL: string; generation: number; used: boolean; restart(): Promise<void> };
type Handle = { baseURL: string; stop(): Promise<void> };

async function exists(path: string) {
  return access(path).then(() => true, () => false);
}
async function waitGone(path: string) {
  for (let i = 0; i < 150 && await exists(path); i++) await new Promise(resolve => setTimeout(resolve, 100));
  if (await exists(path)) throw new Error('Instance cleanup left ' + path);
}
async function startInstance(): Promise<Handle> {
  const child = spawn(process.execPath, ['scripts/ui-instance.mjs', 'serve'], { windowsHide: true });
  let output = '';
  const ready = new Promise<void>((resolve, reject) => {
    child.stdout.on('data', chunk => { output += chunk; if (output.includes('UI_TEST_URL=')) resolve(); });
    child.stderr.on('data', chunk => { output += chunk; });
    child.once('error', reject);
    child.once('exit', code => reject(new Error('Instance exited: ' + code + '\n' + output)));
  });
  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const state = JSON.parse(await readFile('.ui-test/instance.json', 'utf8'));
    const exited = once(child, 'exit');
    const response = await fetch(state.control + '/stop', { method: 'POST', headers: { 'X-Instance': state.token } });
    if (!response.ok) throw new Error('Instance cleanup refused');
    await exited;
    await waitGone(state.data);
    await waitGone('.ui-test/instance.json');
  };
  try { await ready; } catch (error) { await stop().catch(() => {}); throw error; }
  const state = JSON.parse(await readFile('.ui-test/instance.json', 'utf8'));
  if (!/^http:\/\/127[.]0[.]0[.]1:[0-9]+$/.test(state.baseURL)) { await stop(); throw new Error('Non-local test origin refused'); }
  return { baseURL: state.baseURL, stop };
}

// One disposable instance per Playwright worker (one worker per project with --workers=1).
// Tests isolate themselves by their own run IDs; a test that needs an untouched instance sets freshInstance.
// A test that deliberately provokes a failure (a routed 404, 503 or aborted request) lists the browser errors it
// expects in expectedErrors; every other test keeps the strict default.
export const test = base.extend<{ freshInstance: boolean; expectedErrors: RegExp[]; instanceLog: void }, { instance: Instance }>({
  freshInstance: [false, { option: true }],
  expectedErrors: [[], { option: true }],
  instance: [async ({}, use) => {
    let handle: Handle | undefined;
    try {
      handle = await startInstance();
      const instance: Instance = {
        baseURL: handle.baseURL, generation: 0, used: false,
        async restart() {
          const previous = handle!;
          handle = undefined;
          await previous.stop();
          handle = await startInstance();
          instance.baseURL = handle.baseURL;
          instance.generation++;
          instance.used = false;
        },
      };
      await use(instance);
    } finally { await handle?.stop(); }
  }, { scope: 'worker', timeout: 150_000 }],
  instanceLog: [async ({ instance, freshInstance }, use, testInfo) => {
    if (freshInstance && instance.used) await instance.restart();
    instance.used = true;
    const generation = instance.generation;
    const start = (await readFile('.ui-test/app.log')).length;
    try { await use(); }
    finally {
      // Attach only this test's slice of the shared instance log.
      const log = await readFile('.ui-test/app.log').catch(() => Buffer.alloc(0));
      const body = instance.generation === generation ? log.subarray(start) : log;
      await testInfo.attach('synthetic-instance-log', { body, contentType: 'text/plain' });
    }
  }, { auto: true, timeout: 150_000 }],
  baseURL: async ({ instance, instanceLog }, use) => {
    await use(instance.baseURL);
  },
  page: async ({ page, expectedErrors }, use) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    page.on('response', response => { if (response.status() >= 400) errors.push(response.status() + ' ' + response.url()); });
    await use(page);
    expect(errors.filter(error => !expectedErrors.some(pattern => pattern.test(error))), 'unexpected browser/HTTP errors').toEqual([]);
  },
});
export { expect };

/** Records each request's outcome, so a startup that times out can say what it was waiting for (#306). */
function watchRequests(page: Page) {
  const open = new Map<Request, number>();
  const answered: string[] = [];
  const failed: string[] = [];
  const label = (request: Request, startedAt: number) =>
    request.method() + ' ' + new URL(request.url()).pathname + ' (' + (Date.now() - startedAt) + ' ms)';
  const onRequest = (request: Request) => { open.set(request, Date.now()); };
  const settle = (list: string[]) => (request: Request) => {
    list.push(label(request, open.get(request) ?? Date.now()));
    open.delete(request);
  };
  const onFinished = settle(answered);
  const onFailed = settle(failed);
  page.on('request', onRequest);
  page.on('requestfinished', onFinished);
  page.on('requestfailed', onFailed);
  return {
    stop() {
      page.off('request', onRequest);
      page.off('requestfinished', onFinished);
      page.off('requestfailed', onFailed);
    },
    report: () => [
      'No answer: ' + ([...open].map(([request, startedAt]) => label(request, startedAt)).join(', ') || 'none'),
      'Failed: ' + (failed.join(', ') || 'none'),
      'Answered: ' + (answered.join(', ') || 'none'),
      'Host load: ' + loadavg()[0].toFixed(1),
    ].join('\n'),
  };
}

/** Pass timeout only to test the report; everyone else waits the configured expect timeout. */
export async function ready(page: Page, timeout?: number) {
  const requests = watchRequests(page);
  try {
    await page.goto('/');
    await expect(page.getByRole('radio')).toHaveCount(3, { timeout });
    await expect(page.locator('#sample option')).toHaveCount(6, { timeout });
    await expect(page.getByRole('button', { name: 'Run onboarding' })).toBeEnabled({ timeout });
    await expect(page.locator('#recent-runs')).not.toContainText('Loading', { timeout });
  } catch (error) {
    throw new Error((error as Error).message + '\n' + requests.report(), { cause: error });
  } finally { requests.stop(); }
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
  await expect(page.locator('#steps > li').first()).toBeVisible();
  await expect(page.locator('#run-status')).toContainText('Done:');
  await expect(page.getByLabel('Recent runs')).toHaveValue(result.runId);
  return result;
}
export async function reopen(page: Page, id: string) {
  await page.reload();
  await expect(page.locator('#recent-runs option[value="' + id + '"]')).toBeAttached();
  await page.getByLabel('Recent runs').selectOption(id);
  await expect(page.locator('#history-status')).toHaveText('Run reopened.');
  await expect(page.locator('#run-meta')).toContainText('run ' + id.slice(0, 8));
}
/** Opens a setup drawer (Payer faults or Connection overrides) if it is closed. */
export async function openDrawer(page: Page, name: 'Payer faults' | 'Connection overrides') {
  const drawer = page.locator('details.drawer').filter({ has: page.locator('summary', { hasText: name }) });
  if (!await drawer.evaluate(element => (element as HTMLDetailsElement).open)) await drawer.locator('summary').click();
  await expect(drawer).toHaveAttribute('open', '');
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
