// Readiness and isolation checks for the disposable instance started per docs/ui-testing.md "Start".
// Read-only: it never starts, stops or changes the instance.
import { readFile } from 'node:fs/promises';
import { connect } from 'node:net';
import { networkInterfaces, tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
export const handlePath = join(root, '.ui-test', 'instance.json');
export const SYNTHETIC_PAYERS = ['fabrikam-synthetic', 'northwind-synthetic', 'tailspin-synthetic'];
export const SEED_SAMPLE = 'order-sign-hospital-bed';
const LOOPBACK_URL = /^http:\/\/127[.]0[.]0[.]1:([0-9]+)$/;
// Same overrides the launcher refuses, plus payer/credential-shaped names that must never reach a verification run.
const CONFIG_OVERRIDE = /^(SPRING_|WORKBENCH_|JAVA_TOOL_OPTIONS$|JDK_JAVA_OPTIONS$|_JAVA_OPTIONS$)/i;
const CREDENTIAL = /(SECRET|PASSWORD|PRIVATE_KEY|CLIENT_ID|CREDENTIAL|PAYER)/i;

/** Resolves true when something accepts a TCP connection on host:port. */
export function listening(host, port, timeoutMs = 1000) {
  return new Promise(done => {
    const socket = connect({ host, port });
    const finish = result => { socket.destroy(); done(result); };
    socket.setTimeout(timeoutMs, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

/** Non-loopback IPv4 addresses of this machine, used to prove the app is not reachable from them. */
export function externalAddresses() {
  return Object.values(networkInterfaces()).flat().filter(a => a && a.family === 'IPv4' && !a.internal).map(a => a.address);
}

async function json(fetchImpl, url) {
  const response = await fetchImpl(url);
  if (!response.ok) throw new Error(url + ' returned ' + response.status);
  return response.json();
}

/**
 * Runs every check and returns [{ name, ok, detail }]. Dependencies are injectable for tests;
 * the defaults read the real handle and probe the real sockets.
 */
export async function runDoctor({
  state, expectedPort, env = process.env, fetchImpl = fetch, probe = listening,
  addresses = externalAddresses(), temp = tmpdir(),
} = {}) {
  const checks = [];
  const check = (name, ok, detail) => checks.push({ name, ok: Boolean(ok), detail });
  if (!state) {
    try { state = JSON.parse(await readFile(handlePath, 'utf8')); }
    catch (error) { check('handle', false, 'no readable .ui-test/instance.json (' + error.code + ')'); return checks; }
  }
  check('handle', state.ready === true && Number.isInteger(state.pid) && Number.isInteger(state.supervisorPid),
    'ready=' + state.ready + ' javaPid=' + state.pid + ' supervisorPid=' + state.supervisorPid);

  const port = LOOPBACK_URL.exec(state.baseURL ?? '')?.[1];
  const portOk = port !== undefined && (expectedPort === undefined || Number(port) === Number(expectedPort));
  check('loopback-url', portOk && LOOPBACK_URL.test(state.control ?? ''),
    'baseURL=' + state.baseURL + (expectedPort === undefined ? '' : ' expectedPort=' + expectedPort));
  if (port === undefined) return checks;

  let health;
  try { health = await json(fetchImpl, state.baseURL + '/actuator/health'); } catch (error) { health = { status: error.message }; }
  check('health', health.status === 'UP', '/actuator/health status=' + health.status);

  const reachable = [];
  for (const address of addresses) if (await probe(address, Number(port))) reachable.push(address);
  // Counts only: the evidence summary is shared, and interface addresses identify the machine.
  check('loopback-only', reachable.length === 0, reachable.length
    ? 'app port ' + port + ' also answers on ' + reachable.length + ' non-loopback address(es)'
    : 'port ' + port + ' refused on ' + addresses.length + ' non-loopback address(es)');

  try {
    const [payers, samples, features] = await Promise.all(['payers', 'samples', 'features']
      .map(path => json(fetchImpl, state.baseURL + '/api/' + path)));
    const ids = payers.map(p => p.payerId).sort();
    check('seed-payers', JSON.stringify(ids) === JSON.stringify(SYNTHETIC_PAYERS), 'payers=' + ids.join(','));
    const sampleIds = samples.map(s => s.id);
    check('seed-samples', sampleIds.includes(SEED_SAMPLE), samples.length + ' samples, ' + SEED_SAMPLE
      + (sampleIds.includes(SEED_SAMPLE) ? ' present' : ' missing'));
    check('custom-endpoints-off', features.customEndpoints === false, 'customEndpoints=' + features.customEndpoints);
  } catch (error) {
    check('seed-payers', false, error.message);
  }

  const data = resolve(state.data ?? '');
  check('data-path', dirname(data) === resolve(temp) && basename(data).startsWith('ui-workbench-'),
    'data=<temp>/' + basename(data));
  check('log-path', resolve(state.log ?? '') === join(root, '.ui-test', 'app.log'), 'log=' + relative(root, resolve(state.log ?? '')));
  const overrides = Object.keys(env).filter(key => CONFIG_OVERRIDE.test(key));
  const credentials = Object.keys(env).filter(key => CREDENTIAL.test(key));
  check('environment', overrides.length === 0 && credentials.length === 0, overrides.length + credentials.length
    ? 'remove ' + [...overrides, ...credentials].join(', ') : 'no configuration overrides or credential variables');
  return checks;
}

export function format(checks) {
  return checks.map(c => (c.ok ? 'PASS ' : 'FAIL ') + c.name.padEnd(22) + c.detail).join('\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const portArg = process.argv.find(arg => arg.startsWith('--expect-port='));
  const checks = await runDoctor({ expectedPort: portArg?.slice('--expect-port='.length) });
  console.log(format(checks));
  process.exitCode = checks.every(c => c.ok) ? 0 : 1;
}
