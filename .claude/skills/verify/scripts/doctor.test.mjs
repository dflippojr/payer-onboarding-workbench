import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { root, runDoctor, SYNTHETIC_PAYERS } from './doctor.mjs';

const temp = join(root, 'synthetic-temp');
const healthyState = {
  ready: true, pid: 101, supervisorPid: 100, baseURL: 'http://127.0.0.1:41000', control: 'http://127.0.0.1:41001',
  data: join(temp, 'ui-workbench-abc123'), log: join(root, '.ui-test', 'app.log'),
};
const healthyApi = {
  '/actuator/health': { status: 'UP' },
  '/api/payers': SYNTHETIC_PAYERS.map(payerId => ({ payerId })),
  '/api/samples': [{ id: 'order-sign-hospital-bed' }, { id: 'order-sign-home-oxygen' }],
  '/api/features': { customEndpoints: false },
};
// Fake API keyed by path; a missing key answers 503 like an app that is still starting.
const fakeFetch = api => async url => {
  const body = api[new URL(url).pathname];
  return { ok: body !== undefined, status: body === undefined ? 503 : 200, json: async () => body };
};
const doctor = ({ state = healthyState, api = healthyApi, env = { PATH: '/bin' }, reachable = [] } = {}) => runDoctor({
  state, expectedPort: 41000, env, temp, fetchImpl: fakeFetch(api),
  addresses: ['192.0.2.10'], probe: async address => reachable.includes(address),
});
const failed = checks => checks.filter(c => !c.ok).map(c => c.name);

test('healthy instance passes every check', async () => {
  const checks = await doctor();
  assert.deepEqual(failed(checks), []);
  assert.ok(checks.length >= 10);
});

test('not ready: handle not published and health down', async () => {
  const checks = await doctor({ state: { ...healthyState, ready: false }, api: { ...healthyApi, '/actuator/health': { status: 'DOWN' } } });
  assert.deepEqual(failed(checks), ['handle', 'health']);
  const unreachable = await doctor({ api: {} });
  assert.ok(failed(unreachable).includes('health'));
  assert.ok(failed(unreachable).includes('seed-payers'));
});

test('non-loopback: wildcard URL, wrong port or reachable from another interface', async () => {
  assert.deepEqual(failed(await doctor({ state: { ...healthyState, baseURL: 'http://0.0.0.0:41000' } })), ['loopback-url']);
  assert.deepEqual(failed(await doctor({ state: { ...healthyState, baseURL: 'http://127.0.0.1:41999' } })), ['loopback-url']);
  const exposed = await doctor({ reachable: ['192.0.2.10'] });
  assert.deepEqual(failed(exposed), ['loopback-only']);
  assert.ok(!exposed.find(c => c.name === 'loopback-only').detail.includes('192.0.2.10'), 'addresses stay out of evidence');
});

test('missing seed: absent or non-synthetic payers, missing sample, custom endpoints on', async () => {
  const api = { ...healthyApi, '/api/payers': [{ payerId: 'northwind-synthetic' }, { payerId: 'acme-real' }],
    '/api/samples': [], '/api/features': { customEndpoints: true } };
  assert.deepEqual(failed(await doctor({ api })), ['seed-payers', 'seed-samples', 'custom-endpoints-off']);
});

test('environment: configuration overrides, credentials and non-disposable data paths fail', async () => {
  const env = { PATH: '/bin', SPRING_CONFIG_IMPORT: 'x', PAYER_CLIENT_SECRET: 'x' };
  const checks = await doctor({ env, state: { ...healthyState, data: join(root, 'real-data') } });
  assert.deepEqual(failed(checks), ['data-path', 'environment']);
  assert.ok(!checks.find(c => c.name === 'environment').detail.includes('=x'), 'values are never printed');
});

