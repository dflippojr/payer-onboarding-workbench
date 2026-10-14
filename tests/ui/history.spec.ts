import type { APIRequestContext, Page, Route } from '@playwright/test';
import { test, expect, ready, runOnboarding } from './fixtures';

// Recent runs, Compare with and the custom-endpoint form on the real page. Failures are provoked with page.route,
// and each failure case lists the browser errors it expects; runs come from POST /api/runs on the disposable
// instance, so every test isolates itself by the ids its own runs return.

type Run = { runId: string; findings: { checkId: string; severity: string }[] };

async function startRun(request: APIRequestContext, extra: Record<string, unknown> = {}): Promise<Run> {
  const response = await request.post('/api/runs', { data: {
    payerId: 'northwind-synthetic', environment: 'SANDBOX', sampleId: 'order-sign-hospital-bed', faults: [], ...extra,
  } });
  expect(response.ok()).toBe(true);
  return response.json();
}
const discoveryDown = { faults: ['discovery-500'] };

const isGet = (route: Route) => route.request().method() === 'GET';
const recent = (page: Page) => page.getByRole('combobox', { name: 'Recent runs' });
const compare = (page: Page) => page.getByRole('combobox', { name: 'Compare with' });
const status = (page: Page) => page.locator('#history-status');

/** Reopens a retained run from Recent runs and waits until it is the run on screen. */
async function show(page: Page, id: string) {
  await recent(page).selectOption(id);
  await expect(page.locator('#run-meta')).toContainText('run ' + id.slice(0, 8));
  await expect(status(page)).toHaveText('Run reopened.');
}

/** Holds the GET for one run until released, so a test can answer requests out of order. */
async function hold(page: Page, id: string) {
  const pattern = '**/api/runs/' + id;
  let open!: () => void;
  let arrive!: () => void;
  const gate = new Promise<void>(resolve => { open = resolve; });
  const reached = new Promise<void>(resolve => { arrive = resolve; });
  await page.route(pattern, async route => { arrive(); await gate; await route.continue(); });
  return {
    reached,
    async release() {
      const answered = page.waitForResponse(response => response.url().endsWith('/api/runs/' + id));
      open();
      await answered;
      // The page reads the body after the response event, so give a stale answer time to (wrongly) render.
      await page.evaluate(() => new Promise(resolve => setTimeout(resolve, 150)));
      await page.unroute(pattern);
    },
  };
}

test('run labels fall back to the short run id and the payer id, and name custom runs Custom', async ({ page }) => {
  const summary = { environment: 'SANDBOX', startedAt: '2026-10-01T12:00:00Z' };
  await page.route('**/api/runs', route => isGet(route) ? route.fulfill({ json: [
    { ...summary, runId: 'aaaaaaaa-0000', payerId: 'northwind-synthetic', startedAt: null, verdict: 'FAIL' },
    { ...summary, runId: 'bbbbbbbb-0000', payerId: 'retired-payer', verdict: 'PASS' },
    { ...summary, runId: 'cccccccc-0000', payerId: 'custom-endpoint', environment: 'STAGING', verdict: 'PASS_WITH_WARNINGS' },
  ] }) : route.fallback());
  await ready(page);
  await expect(recent(page).locator('option').filter({ hasText: / · / })).toHaveText([
    'run aaaaaaaa · Northwind · SANDBOX · Fail',
    '12:00:00 · retired-payer · SANDBOX · Pass',
    '12:00:00 · Custom · STAGING · Warn',
  ]);
});

test('empty history is understandable and a successful run refreshes the collection', async ({ page }) => {
  let served = false;
  await page.route('**/api/runs', route => {
    if (!isGet(route) || served) return route.fallback();
    served = true;
    return route.fulfill({ json: [] });
  });
  await ready(page);
  await expect(recent(page)).toContainText('No recent runs yet');
  await expect(status(page)).toContainText('Run onboarding');
  const result = await runOnboarding(page);
  await expect(recent(page)).toHaveValue(result.runId);
  await expect(page.getByRole('button', { name: 'Run onboarding' })).toBeEnabled();
});

test.describe('failures while loading or reopening runs', () => {
  test.describe('a run that is no longer retained', () => {
    test.use({ expectedErrors: [/\b404\b/] });

    test('evicted selection refreshes history, announces the error and clears the stale report and result', async ({ page, request }) => {
      const first = await startRun(request);
      const second = await startRun(request);
      await ready(page);
      await show(page, first.runId);
      await expect(page.locator('#report-actions')).toBeVisible();
      await page.route('**/api/runs/' + second.runId, route => route.fulfill({ status: 404, json: { detail: 'Synthetic: evicted' } }));
      await recent(page).selectOption(second.runId);
      await expect(status(page)).toContainText('no longer available');
      await expect(page.locator('#report-actions')).toBeHidden();
      await expect(page.locator('#report-link')).not.toHaveAttribute('href', /.+/);
      await expect(page.locator('#steps > li')).toHaveCount(0);
      await expect(page.locator('#findings')).toBeEmpty();
      // The collection was fetched again, and the form can still run.
      await expect(recent(page)).toHaveValue('');
      await expect(page.getByRole('button', { name: 'Run onboarding' })).toBeEnabled();
    });

    test('evicted comparison run refreshes history, clears the comparison and says so', async ({ page, request }) => {
      const shown = await startRun(request, discoveryDown);
      const baseline = await startRun(request);
      const evicted = await startRun(request);
      await ready(page);
      await show(page, shown.runId);
      await compare(page).selectOption(baseline.runId);
      const comparison = page.getByRole('region', { name: 'Changes since run ' + baseline.runId.slice(0, 8) });
      await expect(comparison).toBeVisible();
      await page.route('**/api/runs/' + evicted.runId, route => route.fulfill({ status: 404, json: { detail: 'Synthetic: evicted' } }));
      await compare(page).selectOption(evicted.runId);
      await expect(status(page)).toContainText('That run is no longer available');
      await expect(page.locator('#comparison')).toBeHidden();
      await expect(compare(page)).toHaveValue('');
      await expect(page.locator('#findings')).toContainText('discovery.reachable');
    });
  });

  test.describe('the collection is unavailable', () => {
    test.use({ expectedErrors: [/\b503\b/] });

    test('failed initial and post-run collection fetches leave the form usable', async ({ page }) => {
      await page.route('**/api/runs', route => isGet(route)
        ? route.fulfill({ status: 503, json: { detail: 'Synthetic: unavailable' } }) : route.fallback());
      await ready(page);
      await expect(status(page)).toContainText('Could not load recent runs');
      const posted = page.waitForResponse(r => r.url().endsWith('/api/runs') && r.request().method() === 'POST');
      await page.getByRole('button', { name: 'Run onboarding' }).click();
      const result = await (await posted).json();
      await expect(page.locator('#run-status')).toContainText('Done:');
      await expect(page.getByRole('button', { name: 'Run onboarding' })).toBeEnabled();
      await expect(page.locator('#report-link')).toHaveAttribute('href', 'api/runs/' + result.runId + '/report?format=html');
    });
  });

  test.describe('the network drops', () => {
    test.use({ expectedErrors: [/Failed to load resource|ERR_FAILED|Load failed/] });

    test('network retrieval errors are announced and do not disable the form', async ({ page, request }) => {
      const run = await startRun(request);
      await ready(page);
      await page.route('**/api/runs/' + run.runId, route => route.abort());
      await recent(page).selectOption(run.runId);
      await expect(status(page)).toContainText('Could not reopen run:');
      await expect(page.getByRole('button', { name: 'Run onboarding' })).toBeEnabled();
    });
  });
});

test('stale response from an earlier selection cannot replace the latest result', async ({ page, request }) => {
  const earlier = await startRun(request);
  const later = await startRun(request, discoveryDown);
  await ready(page);
  const held = await hold(page, earlier.runId);
  await recent(page).selectOption(earlier.runId);
  await held.reached;
  await show(page, later.runId);
  await held.release();
  await expect(page.locator('#run-meta')).toContainText('run ' + later.runId.slice(0, 8));
  await expect(page.locator('#findings')).toContainText('discovery.reachable');
  await expect(page.locator('#results-heading')).toHaveText('Not ready: 1 failing check');
});

test('selectors use native controls with an accessible label and a polite live status', async ({ page }) => {
  await ready(page);
  await expect(recent(page)).toHaveAttribute('aria-describedby', 'history-status');
  await expect(compare(page)).toHaveAttribute('aria-describedby', 'history-status');
  const live = page.getByRole('status', { includeHidden: true }).and(page.locator('#history-status'));
  await expect(live).toHaveAttribute('aria-live', 'polite');
});

test('SMART custom auth shows token endpoint and key id and submits the required fields', async ({ page, request }) => {
  await page.route('**/api/features', route => route.fulfill({ json: { customEndpoints: true } }));
  // The custom run never reaches the app: the POST is answered here with a real run's result.
  const canned = await startRun(request);
  const posted: { customEndpoint: Record<string, string | null>; faults: string[] }[] = [];
  await page.route('**/api/runs', route => {
    if (isGet(route)) return route.fallback();
    posted.push(route.request().postDataJSON());
    return route.fulfill({ json: canned });
  });
  await page.goto('/');
  await expect(page.getByRole('radio')).toHaveCount(4);
  await expect(page.getByRole('button', { name: 'Run onboarding' })).toBeEnabled();
  await expect(recent(page)).not.toContainText('Loading');
  await page.getByRole('radio', { name: /Your own endpoint/ }).check();
  const custom = page.locator('#custom-endpoint');
  await expect(custom).toBeVisible();
  const field = (label: string | RegExp) => custom.getByLabel(label);
  const shown = async (token: boolean, key: boolean, credential: boolean) => {
    await expect(field('Client id')).toBeVisible({ visible: credential });
    await expect(field('Token endpoint')).toBeVisible({ visible: token });
    await expect(field('Key id (kid)')).toBeVisible({ visible: key });
    await expect(field(/^Credential/)).toBeVisible({ visible: credential });
  };
  for (const [auth, token, key, credential] of [
    ['None', false, false, false], ['OAuth2 client credentials', true, false, true],
    ['CDS Hooks client JWT', false, true, true], ['SMART Backend Services (private_key_jwt)', true, true, true],
  ] as const) {
    await field('Authentication').selectOption({ label: auth });
    await shown(token, key, credential);
  }
  const values = { baseUrl: 'http://127.0.0.1:18090', clientId: 'synthetic-client',
    tokenEndpoint: 'http://127.0.0.1:18090/oauth/token', keyId: 'synthetic-kid', credential: '<synthetic test credential>' };
  await field('Base URL').fill(values.baseUrl);
  await field('Client id').fill(values.clientId);
  await field('Token endpoint').fill(values.tokenEndpoint);
  await field('Key id (kid)').fill(values.keyId);
  await field(/^Credential/).fill(values.credential);
  await page.getByRole('button', { name: 'Run onboarding' }).click();
  await expect(page.locator('#run-status')).toContainText('Done:');
  expect(posted).toHaveLength(1);
  expect(posted[0].customEndpoint).toEqual({ ...values, authType: 'OAUTH2_PRIVATE_KEY_JWT' });
  expect(posted[0].faults).toEqual([]);
});

test('comparison names unchanged checks and labels a later baseline run', async ({ page, request }) => {
  // The run on screen is the earlier one, with a wrong IG version; the later run is healthy.
  const wrongIg = await startRun(request, { connection: { igVersion: '9.9.9' } });
  const healthy = await startRun(request);
  await ready(page);
  await show(page, wrongIg.runId);
  await compare(page).selectOption(healthy.runId);
  await expect(status(page)).toHaveText('Comparison shown.');
  await expect(page.locator('#comparison-note')).toHaveText(
    /^Later run \d\d:\d\d:\d\d UTC \(Pass\) compared with the run on screen, \d\d:\d\d:\d\d UTC \(Fail\)$/);
  const comparison = page.getByRole('region', { name: 'Changes since run ' + healthy.runId.slice(0, 8) });
  await expect(comparison.getByRole('row', { name: /ig\.version/ })).toContainText('Newly failing');
  await expect(comparison.getByText(/^Fixed or better: none\. Unchanged: \d+ checks? \(.+\)\.$/)).toBeVisible();
});

test('stale comparison fetch is ignored after a newer selection, a reopen or a new run', async ({ page, request }) => {
  const shown = await startRun(request);
  const baseline = await startRun(request);
  const other = await startRun(request, discoveryDown);
  await ready(page);
  const heading = page.locator('#comparison-heading');
  const comparison = page.locator('#comparison');
  const lateFailure = page.locator('#comparison-body').getByText('discovery.reachable');

  // A newer baseline wins over a slower earlier pick.
  await show(page, shown.runId);
  let held = await hold(page, other.runId);
  await compare(page).selectOption(other.runId);
  await held.reached;
  await compare(page).selectOption(baseline.runId);
  await expect(heading).toHaveText('Changes since run ' + baseline.runId.slice(0, 8));
  await held.release();
  await expect(heading).toHaveText('Changes since run ' + baseline.runId.slice(0, 8));
  await expect(lateFailure).toHaveCount(0);

  // Reopening a run closes the comparison for good.
  held = await hold(page, other.runId);
  await compare(page).selectOption(other.runId);
  await held.reached;
  await show(page, baseline.runId);
  await held.release();
  await expect(comparison).toBeHidden();

  // So does a new run.
  await show(page, shown.runId);
  held = await hold(page, other.runId);
  await compare(page).selectOption(other.runId);
  await held.reached;
  await runOnboarding(page);
  await held.release();
  await expect(comparison).toBeHidden();
  await expect(compare(page)).toBeEnabled();
});
