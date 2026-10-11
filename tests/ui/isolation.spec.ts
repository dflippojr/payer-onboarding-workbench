import { readFile } from 'node:fs/promises';
import { test, expect } from './fixtures';

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
