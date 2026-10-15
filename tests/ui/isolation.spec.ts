import { readFile } from 'node:fs/promises';
import { test, expect, ready } from './fixtures';

// Isolation is checked on an instance no earlier test in this worker has touched.
test.use({ freshInstance: true });

test('disposable instance exposes only generated loopback synthetic payers', async ({ request }) => {
  const state = JSON.parse(await readFile('.ui-test/instance.json', 'utf8'));
  expect(state.baseURL).toMatch(/^http:\/\/127[.]0[.]0[.]1:[0-9]+$/);
  expect(state.data).toMatch(/ui-workbench-/);
  const features = await request.get('/api/features');
  expect(await features.json()).toEqual({ customEndpoints: false });
  const payers = await (await request.get('/api/payers')).json();
  expect(payers.map((p: { payerId: string }) => p.payerId).sort()).toEqual([
    'fabrikam-synthetic', 'northwind-synthetic', 'tailspin-synthetic',
  ]);
  for (const payer of payers) for (const connection of payer.connections) {
    expect(connection.baseUrl).toMatch(/^https:\/\/127[.]0[.]0[.]1:\d+$/);
    expect(connection.environment).toBe('SANDBOX');
  }
  const rejected = await request.post('/api/runs', { data: {
    sampleId: 'order-sign-hospital-bed', customEndpoint: { baseUrl: 'https://payer.invalid', authType: 'NONE' },
  } });
  expect(rejected.status()).toBe(400);
  expect((await rejected.text()).toLowerCase()).toContain('disabled');
});

test('the custom endpoint form and picker stay hidden while the feature is off', async ({ page }) => {
  await ready(page);
  await expect(page.locator('#custom-endpoint')).toBeHidden();
  await expect(page.getByRole('group', { name: 'Your payer endpoint' })).toHaveCount(0);
  await expect(page.getByRole('radio')).toHaveCount(3);
  await expect(page.getByRole('radio', { name: /Your own endpoint/ })).toHaveCount(0);
  await expect(page.locator('input[name="payerId"][value="__custom__"]')).toHaveCount(0);
});
