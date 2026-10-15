import { expect, type Page } from '@playwright/test';
import { ready, openDrawer } from './fixtures';

// Only the browser feature response is changed. The disposable server keeps custom endpoints
// disabled, so the submitted form is checked at its real 400 boundary without contacting a payer.
export async function customEndpointForm(page: Page, screenshot: () => Promise<void> = async () => {}) {
  await ready(page);
  await page.route('**/api/features', route => route.fulfill({ json: { customEndpoints: true } }));
  await page.reload();
  await expect(page.getByRole('radio')).toHaveCount(4);
  await expect(page.locator('#recent-runs')).not.toContainText('Loading');
  await openDrawer(page, 'Payer faults');
  const fault = page.getByRole('checkbox', { name: 'Discovery is down' });
  await fault.check();
  const storedHint = await page.locator('#baseUrl-hint').textContent();
  await page.getByRole('radio', { name: 'Your own endpoint' }).check();
  await expect(page.locator('#faults-drawer')).toBeHidden();
  await expect(fault).toBeHidden();
  await expect(page.locator('#custom-endpoint')).toBeVisible();
  await expect(page.locator('#igVersion-hint')).toHaveText('default: 2.0.1');
  await expect(page.locator('#overrides-state')).toHaveText('Endpoint settings');
  await page.locator('#customBaseUrl').fill('http://127.0.0.1:9/ok');
  await expect(page.locator('#baseUrl-hint')).toHaveText('supplied: http://127.0.0.1:9/ok');
  await page.locator('#customAuthType').selectOption('OAUTH2_CLIENT_CREDENTIALS');
  await page.locator('#customClientId').fill('original-client');
  await expect(page.locator('#clientId-hint')).toHaveText('supplied: original-client');
  await openDrawer(page, 'Connection overrides');
  await page.locator('#baseUrlSuffix').fill('/r4');
  await page.locator('#igVersion').fill('2.2.1');
  await page.locator('#clientId').fill('edited-client');
  await expect(page.locator('#overrides-state')).toContainText('3 changed');
  await screenshot();

  const submitted = page.waitForResponse(r => r.url().endsWith('/api/runs') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Run onboarding' }).click();
  const response = await submitted;
  expect(response.status()).toBe(400);
  const request = response.request().postDataJSON();
  expect(request.faults).toEqual([]);
  expect(request.customEndpoint).toMatchObject({ baseUrl: 'http://127.0.0.1:9/ok', clientId: 'original-client' });
  expect(request.connection).toEqual({ baseUrlSuffix: '/r4', igVersion: '2.2.1', clientId: 'edited-client' });
  await expect(page.locator('#run-status')).toContainText('Custom endpoints are disabled');

  await page.locator('input[value="northwind-synthetic"]').check();
  await expect(page.locator('#custom-endpoint')).toBeHidden();
  await expect(page.locator('#faults-drawer')).toBeVisible();
  await expect(fault).toBeVisible();
  await expect(fault).toBeChecked();
  await expect(page.locator('#baseUrl-hint')).toHaveText(storedHint!);
  await page.getByRole('button', { name: 'Reset faults and settings' }).click();
  await expect(fault).not.toBeChecked();
  await expect(page.locator('#overrides-state')).toHaveText('Stored settings');
}
