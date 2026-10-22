import { readFile } from 'node:fs/promises';
import { test, expect, ready, runOnboarding, reopen, audit, auditEvent, openDrawer } from './fixtures';

test('J01/J05/J06 healthy northwind, reload, history and reports', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await ready(page);
  await page.locator('input[value="northwind-synthetic"]').check();
  await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
  const result = await runOnboarding(page);
  await expect(page.locator('#run-status')).toHaveText('Done: no failures.');
  await expect(page.locator('#steps .failed')).toHaveCount(0);
  await expect(page.locator('#verdict-word')).toHaveText(/^Pass/);
  await expect(page.locator('#results-heading')).toHaveText(/^Every step passed/);
  await expect(page.locator('#verdict-check')).toBeHidden();
  // Passing checks stay collapsed.
  await expect(page.locator('#findings .group.PASS details')).not.toHaveAttribute('open', '');
  await audit('run.completed', result.runId, 'northwind-synthetic');
  await reopen(page, result.runId);
  await auditEvent('run.read', result.runId);
  await openDrawer(page, 'Connection overrides');
  await page.locator('#clientId').fill('synthetic-unsent');
  await page.getByLabel('Sample request').selectOption('order-sign-home-oxygen');
  let posts = 0;
  page.on('request', r => { if (r.method() === 'POST') posts++; });
  await page.getByLabel('Recent runs').selectOption('');
  await page.getByLabel('Recent runs').selectOption(result.runId);
  await expect(page.locator('#history-status')).toHaveText('Run reopened.');
  await expect(page.locator('#clientId')).toHaveValue('synthetic-unsent');
  await expect(page.getByLabel('Sample request')).toHaveValue('order-sign-home-oxygen');
  expect(posts).toBe(0);
  for (const format of ['html', 'md', 'json']) {
    await page.getByLabel('Report format').selectOption(format);
    const downloaded = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Download report' }).click();
    const download = await downloaded;
    const report = await readFile((await download.path())!, 'utf8');
    expect(report).toContain(result.runId);
    expect(report.toLowerCase()).toContain('synthetic');
    expect(report).toContain('PASS');
    await auditEvent('report.rendered', result.runId, { reportFormat: format });
  }
  expect(errors).toEqual([]);
});

test('each payer radio sends its payer id in the run request', async ({ page }) => {
  await ready(page);
  await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
  const payerIds = ['northwind-synthetic', 'fabrikam-synthetic', 'tailspin-synthetic'];
  const posted: string[] = [];
  await page.route('**/api/runs', async route => {
    if (route.request().method() === 'POST') posted.push(route.request().postDataJSON().payerId);
    await route.continue();
  });
  for (const payerId of payerIds) {
    await page.locator('input[value="' + payerId + '"]').check();
    await runOnboarding(page);
  }
  expect(posted).toEqual(payerIds);
});

test('J02/J03 failure evidence, reload and reset faults/settings', async ({ page }) => {
  await ready(page);
  await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
  await expect(page.locator('#faults-state')).toHaveText('None on');
  await openDrawer(page, 'Payer faults');
  await page.getByRole('checkbox', { name: 'Discovery is down' }).check();
  await expect(page.locator('#faults-state')).toHaveText('1 on: Discovery is down');
  const failed = await runOnboarding(page);
  // Verdict first: what broke, the failing check, its Fix and the report download, before the timeline.
  await expect(page.locator('#verdict-word')).toHaveText('Fail · broke at Discovery');
  await expect(page.locator('#results-heading')).toHaveText('Not ready: 1 failing check');
  await expect(page.locator('#run-meta')).toContainText('fault: Discovery is down');
  await expect(page.locator('#verdict-check')).toContainText('discovery.reachable');
  await expect(page.locator('#verdict-check .fix')).toBeVisible();
  await expect(page.locator('#results').getByRole('link', { name: 'Download report' })).toBeVisible();
  await expect(page.locator('#findings .finding-ref')).toContainText('discovery.reachable');
  await expect(page.locator('#findings .finding-ref')).toContainText('Shown in the verdict above');
  await audit('run.completed', failed.runId, 'northwind-synthetic');
  await reopen(page, failed.runId);
  for (const format of ['html', 'md', 'json']) {
    await page.getByLabel('Report format').selectOption(format);
    const pending = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Download report' }).click();
    const report = await readFile((await (await pending).path())!, 'utf8');
    expect(report).toContain(failed.runId);
    expect(report).toContain('FAIL');
    expect(report.toLowerCase()).toContain('synthetic');
    await auditEvent('report.rendered', failed.runId, { reportFormat: format });
  }
  await expect(page.locator('#steps .step.failed h3')).toHaveText(['Discovery', 'Run diagnostics']);
  // The three skipped steps fold into one row that names the cause.
  await expect(page.locator('#steps .step.skipped')).toHaveCount(1);
  await expect(page.locator('#steps .step.skipped')).toContainText(
    'Authenticate, Send sample hook request and Parse response did not run because Discovery failed.');
  await expect(page.locator('#step-counts')).toHaveText('1 passed · 2 failed · 3 skipped');
  // An exchange is one line that opens into the request and response side by side.
  const exchange = page.locator('#steps .step.failed details.exchange').first();
  await expect(exchange.locator('summary')).toContainText('GET');
  await expect(exchange.locator('summary .chip')).toHaveText('500');
  await exchange.locator('summary').press('Enter');
  await expect(exchange.locator('.exchange-grid')).toContainText('Request headers');
  await expect(exchange.locator('.exchange-grid')).toContainText('Response body');
  await page.setViewportSize({ width: 1440, height: 900 });
  const [request, response] = await exchange.locator('.exchange-grid > div').all();
  expect(Math.round((await request.boundingBox())!.y)).toBe(Math.round((await response.boundingBox())!.y));
  const evidence = page.locator('#verdict-check summary').first();
  await evidence.press('Enter');
  await expect(page.locator('#verdict-check details[open]').first()).toBeVisible();
  await openDrawer(page, 'Payer faults');
  await page.getByRole('checkbox', { name: 'Discovery is down' }).check();
  await openDrawer(page, 'Connection overrides');
  await page.locator('#baseUrlSuffix').fill('/r4');
  await page.locator('#igVersion').fill('2.0.1');
  await page.locator('#clientId').fill('synthetic-edit');
  await expect(page.locator('#overrides-state')).toHaveText('3 changed: Base URL suffix and 2 more');
  await page.getByRole('button', { name: 'Reset faults and settings' }).click();
  for (const id of ['baseUrlSuffix', 'igVersion', 'clientId']) await expect(page.locator('#' + id)).toHaveValue('');
  await expect(page.locator('input[name="fault"]:checked')).toHaveCount(0);
  await expect(page.locator('#faults-state')).toHaveText('None on');
  await expect(page.locator('#overrides-state')).toHaveText('Stored settings');
  await runOnboarding(page);
  await expect(page.locator('#run-status')).toHaveText('Done: no failures.');
});

test('J05 compare a healthy run with a Discovery-down run', async ({ page }) => {
  await ready(page);
  await expect(page.getByLabel('Compare with')).toBeDisabled();
  await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
  const healthy = await runOnboarding(page);
  await openDrawer(page, 'Payer faults');
  await page.getByRole('checkbox', { name: 'Discovery is down' }).check();
  const failed = await runOnboarding(page);
  const compare = page.getByLabel('Compare with');
  await expect(compare).toBeEnabled();
  await expect(compare.locator('option[value="' + failed.runId + '"]')).toHaveCount(0);
  // Run labels: UTC time · payer short name · environment · verdict word, whole in both selects at 390 px.
  const recent = page.getByLabel('Recent runs');
  await expect(recent.locator('option[value="' + failed.runId + '"]')).toHaveText(/^\d\d:\d\d:\d\d · Northwind · SANDBOX · Fail$/);
  await expect(compare.locator('option[value="' + healthy.runId + '"]')).toHaveText(/^\d\d:\d\d:\d\d · Northwind · SANDBOX · Pass$/);
  const viewport = page.viewportSize()!;
  await page.setViewportSize({ width: 390, height: 844 });
  for (const select of [recent, compare]) {
    // Every run label fits beside the select's arrow, and so do the widest a synthetic payer can produce: only
    // SANDBOX has a stored connection, so STAGING and PRODUCTION runs always fail. Text is measured in Arial, whose
    // metrics Liberation Sans shares on Linux and which is close to the SF Pro and Roboto phones show for system-ui;
    // the runners' own system-ui fallback, DejaVu Sans, is far wider than any phone font.
    const room = await select.evaluate((el: HTMLSelectElement) => {
      const style = getComputedStyle(el);
      const context = document.createElement('canvas').getContext('2d')!;
      context.font = `${style.fontSize} Arial, "Liberation Sans"`;
      const inner = el.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
      const labels = [...el.options].filter(o => o.value).map(o => o.text)
        .concat('00:00:00 · Northwind · SANDBOX · Warn', '00:00:00 · Northwind · PRODUCTION · Fail').map(text => context.measureText(text).width);
      return inner - Math.max(...labels);
    });
    expect(room).toBeGreaterThan(20);
  }
  await page.setViewportSize(viewport);
  await compare.focus();
  await compare.selectOption(healthy.runId);
  await expect(page.locator('#history-status')).toHaveText('Comparison shown.');
  const comparison = page.getByRole('region', { name: 'Changes since run ' + healthy.runId.slice(0, 8) });
  await expect(comparison).toBeVisible();
  await expect(page.locator('#comparison-note')).toHaveText(
    /^Earlier run \d\d:\d\d:\d\d UTC \(Pass\) compared with the run on screen, \d\d:\d\d:\d\d UTC \(Fail\)$/);
  await expect(comparison.locator('.tile dd').first()).toHaveText('Pass → Fail Worse');
  await expect(comparison.locator('.tile dd').nth(1)).toHaveText('every step passed → Discovery');
  await expect(comparison.locator('.step-changes li').first()).toHaveText('Discovery, Run diagnostics Passed → Failed');
  const changed = comparison.getByRole('table').first();
  await expect(changed.getByRole('columnheader')).toHaveText(['Check', 'Earlier run', 'This run', 'Change']);
  await expect(changed.getByRole('row', { name: /discovery\.reachable/ })).toContainText('Newly failing');
  await expect(comparison.getByText(/^Fixed or better: none\. Unchanged: \d+ checks? \(.+\)\.$/)).toBeVisible();
  // The one-sided group is collapsed and says why its checks are not counted.
  const oneSided = comparison.locator('details.one-sided');
  await expect(oneSided).not.toHaveAttribute('open', '');
  await expect(oneSided.locator('summary')).toHaveText(/^Only in one run · \d+ checks?$/);
  await oneSided.locator('summary').click();
  await expect(oneSided.getByText(/usually because a step was skipped/)).toBeVisible();
  await expect(oneSided.getByRole('row', { name: /auth\.token/ })).toContainText('Earlier run only');
  await auditEvent('run.read', healthy.runId);
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole('button', { name: 'Stop comparing' }).click();
  await expect(comparison).toBeHidden();
  await expect(page.locator('#history-status')).toHaveText('Comparison closed.');
  await expect(compare).toBeFocused();
  await expect(compare).toHaveValue('');
  await compare.selectOption(healthy.runId);
  await expect(comparison).toBeVisible();
  await page.getByLabel('Recent runs').selectOption(healthy.runId);
  await expect(comparison).toBeHidden();
});

test('running state shows the pending steps and hides the previous run', async ({ page }) => {
  await ready(page);
  await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
  const previous = await runOnboarding(page);
  await openDrawer(page, 'Payer faults');
  await page.getByRole('checkbox', { name: 'Payer is slow' }).check();
  // Hold the POST so the running state can be inspected, then send it without the slow fault so the
  // test does not wait about 11 s per call. The page built its running copy from the form as submitted.
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/api/runs', async route => {
    if (route.request().method() !== 'POST') return route.continue();
    await held;
    await route.continue({ postData: JSON.stringify({ ...route.request().postDataJSON(), faults: [] }) });
  });
  const response = page.waitForResponse(r => r.url().endsWith('/api/runs') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Run onboarding' }).click();
  const results = page.locator('.results');
  await expect(results).toHaveAttribute('aria-busy', 'true');
  await expect(page.getByRole('button', { name: 'Running…' })).toBeDisabled();
  await expect(page.locator('#verdict-word')).toHaveText('Running');
  await expect(page.locator('#results-heading')).toHaveText('Onboarding Northwind Health (synthetic)');
  await expect(page.locator('#run-meta')).toContainText('SANDBOX · ');
  await expect(page.locator('#run-meta')).toContainText('fault on: Payer is slow. The slow-response fault holds each response for about 11 s');
  const pending = page.locator('#running-steps .step.pending');
  await expect(pending.locator('h3')).toHaveText(
    ['Resolve connection', 'Discovery', 'Authenticate', 'Send sample hook request', 'Parse response', 'Run diagnostics']);
  await expect(pending.locator('.latency')).toHaveText(Array(6).fill('waiting'));
  await expect(page.getByRole('list', { name: 'Steps waiting for the run' })).toBeVisible();
  // The previous run is no longer shown as the current result.
  await expect(page.locator('#steps-card')).toBeHidden();
  await expect(page.locator('#findings-card')).toBeHidden();
  await expect(page.getByRole('link', { name: 'Download report' })).toBeHidden();
  await expect(page.locator('#running-note')).toHaveText(/^The previous run \(\d\d:\d\d:\d\d UTC, Pass\) is still in Recent runs\.$/);
  await expect(page.getByLabel('Compare with')).toBeDisabled();
  await expect(page.getByLabel('Compare with')).toHaveValue('');
  await expect(page.getByLabel('Compare with').locator('option')).toHaveText(['Show a run first']);
  await expect(page.getByLabel('Recent runs')).toBeDisabled();
  await expect(page.getByLabel('Recent runs')).toHaveValue(previous.runId);
  // The bar is indeterminate, and static under reduced motion.
  const bar = page.locator('#run-track > span');
  await expect(bar).toBeVisible();
  expect(await bar.evaluate(el => getComputedStyle(el).animationName)).toBe('track');
  await page.emulateMedia({ reducedMotion: 'reduce' });
  expect(await bar.evaluate(el => getComputedStyle(el).animationName)).toBe('none');
  await page.emulateMedia({ reducedMotion: null });
  release();
  const result = await (await response).json();
  await page.unroute('**/api/runs');
  await expect(page.locator('#run-status')).toHaveText('Done: no failures.');
  await expect(results).not.toHaveAttribute('aria-busy');
  await expect(page.locator('#running-steps')).toBeHidden();
  await expect(page.locator('#run-track')).toBeHidden();
  await expect(page.locator('#running-note')).toBeHidden();
  await expect(page.locator('#steps > li').first()).toBeVisible();
  await expect(page.locator('#verdict-word')).toHaveText('Pass');
  await expect(page.locator('#run-meta')).toContainText('run ' + result.runId.slice(0, 8));
  await expect(page.locator('#results-heading')).toBeFocused();
  await expect(page.getByRole('button', { name: 'Run onboarding' })).toBeEnabled();
  await expect(page.getByLabel('Recent runs')).toHaveValue(result.runId);
});

test('J04 unavailable environment produces retained diagnostic run', async ({ page }) => {
  await ready(page);
  await page.getByRole('combobox', { name: 'Environment', exact: true }).selectOption('STAGING');
  const result = await runOnboarding(page);
  await expect(page.locator('#verdict-word')).toHaveText('Fail · broke at Resolve connection');
  await audit('run.completed', result.runId, 'northwind-synthetic', 'STAGING');
  await reopen(page, result.runId);
  await expect(page.locator('#run-meta')).toContainText('STAGING');
});

test('live resize preserves open disclosure, unsent settings, selection and focus', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  await page.setViewportSize({ width: 1440, height: 900 });
  await ready(page);
  await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
  await runOnboarding(page);
  const summary = page.getByText('Step details', { exact: true }).first();
  await summary.click();
  await openDrawer(page, 'Connection overrides');
  await page.locator('#clientId').fill('synthetic-resize');
  await page.getByLabel('Sample request').selectOption('order-sign-home-oxygen');
  await page.locator('#clientId').focus();
  for (const width of [768, 375, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await expect(page.locator('#clientId')).toHaveValue('synthetic-resize');
    await expect(page.locator('#clientId')).toBeFocused();
    await expect(page.getByLabel('Sample request')).toHaveValue('order-sign-home-oxygen');
    await expect(page.locator('#steps details[open]').first()).toBeVisible();
  }
  await summary.click();
  await expect(page.locator('#steps details[open]')).toHaveCount(0);
  await page.getByRole('button', { name: 'Reset faults and settings' }).click();
  await expect(page.locator('#clientId')).toHaveValue('');
  expect(errors).toEqual([]);
});

test('J07 keyboard reaches form and submits with results focus', async ({ page, browserName }) => {
  await ready(page);
  await page.keyboard.press('Tab');
  const skip = page.getByRole('link', { name: 'Skip to results' });
  if (browserName !== 'webkit') await expect(skip).toBeFocused();
  // WebKit link traversal depends on its platform preference; either native path must reach the radio.
  if (await skip.evaluate(element => element === document.activeElement)) await page.keyboard.press('Tab');
  await expect(page.locator('input[value="northwind-synthetic"]')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('combobox', { name: 'Environment', exact: true })).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(page.locator('input[value="northwind-synthetic"]')).toBeFocused();
  await page.keyboard.press('ArrowRight');
  await expect(page.locator('input[value="fabrikam-synthetic"]')).toBeChecked();
  // Faults sit in a closed native drawer: Enter on its summary opens it and Tab reaches the first fault.
  const faults = page.locator('#faults-drawer');
  await faults.locator('summary').focus();
  await page.keyboard.press('Enter');
  await expect(faults).toHaveAttribute('open', '');
  await page.keyboard.press('Tab');
  await expect(page.locator('#faults input[name="fault"]').first()).toBeFocused();
  await page.getByRole('checkbox', { name: 'Discovery is down' }).focus();
  await page.keyboard.press('Space');
  await expect(page.getByRole('checkbox', { name: 'Discovery is down' })).toBeChecked();
  await expect(page.locator('#faults-state')).toHaveText('1 on: Discovery is down');
  // Space on the summary closes it again; the summary still says what is on.
  await faults.locator('summary').focus();
  await page.keyboard.press('Space');
  await expect(faults).not.toHaveAttribute('open', '');
  await expect(page.locator('#faults-state')).toHaveText('1 on: Discovery is down');
  await page.getByRole('button', { name: 'Reset faults and settings' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('input[name="fault"]:checked')).toHaveCount(0);
  await page.getByRole('button', { name: 'Run onboarding' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#run-status')).toContainText('Done:');
  await expect(page.locator('#results-heading')).toBeFocused();
  // Exercise link activation/focus independently of the browser's native traversal preference.
  await page.getByRole('link', { name: 'Skip to results' }).focus();
  await expect(page.getByRole('link', { name: 'Skip to results' })).toBeInViewport();
  await page.keyboard.press('Enter');
  await expect(page.locator('#results-heading')).toBeFocused();
});

test('J08 connection edit belongs to one retained run and has matching audit metadata', async ({ page }) => {
  await ready(page);
  await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
  await openDrawer(page, 'Connection overrides');
  await page.locator('#igVersion').fill('2.0.1');
  const edited = await runOnboarding(page);
  expect(edited.steps[0].details.edited).toEqual({ igVersion: '2.0.1' });
  await audit('run.completed', edited.runId, 'northwind-synthetic');
  await auditEvent('run.completed', edited.runId, { overrides: ['igVersion'] });
  await reopen(page, edited.runId);
  const details = page.getByText('Step details', { exact: true }).first();
  await details.click();
  await expect(page.locator('#steps details[open]').first()).toContainText('2.0.1');
  await page.getByRole('button', { name: 'Reset faults and settings' }).click();
  const normal = await runOnboarding(page);
  expect(normal.steps[0].details.connection.igVersion).toBe('2.2.1');
  expect(normal.steps[0].details.edited).toEqual({});
  await auditEvent('run.completed', normal.runId, { overrides: [] });
  await reopen(page, normal.runId);
  await page.getByText('Step details', { exact: true }).first().click();
  await expect(page.locator('#steps details[open]').first()).toContainText('2.2.1');
});

test('synthetic banner and incomplete coverage fault explain the supported scenario', async ({ page }) => {
  await ready(page);
  await page.setViewportSize({ width: 320, height: 900 });
  await expect(page.getByRole('note')).toContainText('All three synthetic payers run inside this app with generated credentials');
  await expect(page.getByRole('note')).toContainText('no real payer, patient or PHI is involved');
  await expect(page.getByRole('note')).toContainText('passing here does not prove real-payer interoperability');
  await openDrawer(page, 'Payer faults');
  const fault = page.getByRole('checkbox', { name: 'Incomplete coverage information' });
  const label = page.locator('.check').filter({ has: fault });
  await expect(label).toContainText('Order-sign responses omit the coverage assertion ID and use an invalid covered value.');
  await expect(label.locator('code')).toHaveText('coverage-info-incomplete');
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await label.click();
  await expect(fault).toBeChecked();
  await fault.focus();
  await page.keyboard.press('Space');
  await expect(fault).not.toBeChecked();
  await page.keyboard.press('Space');
  await expect(fault).toBeChecked();
  await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
  await runOnboarding(page);
  await expect(page.locator('#verdict-check, #findings .finding.FAIL').filter({ hasText: 'response.coverage-information' })).toHaveCount(1);
});

test.describe('the payer is busy', () => {
  test.use({ expectedErrors: [/\b409\b/] });

  test('a run refused because the payer is busy shows the 409 reason and keeps the previous result', async ({ page }) => {
    await ready(page);
    await page.locator('input[value="fabrikam-synthetic"]').check();
    await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
    const previous = await runOnboarding(page);
    // The server answers this way when another run holds the payer for all of workbench.request-timeout
    // (PayerLockTest drives the real 409); waiting 15 s for a real one here would slow every project.
    const detail = 'another run against fabrikam-synthetic is in progress; try again when it finishes';
    await page.route('**/api/runs', route => route.request().method() === 'POST'
      ? route.fulfill({ status: 409, contentType: 'application/problem+json',
          json: { type: 'about:blank', title: 'Conflict', status: 409, detail, instance: '/api/runs' } })
      : route.continue());
    const refused = page.waitForResponse(r => r.url().endsWith('/api/runs') && r.request().method() === 'POST');
    await page.getByRole('button', { name: 'Run onboarding' }).click();
    expect((await refused).status()).toBe(409);
    await expect(page.locator('#run-status')).toHaveText('Run not started: ' + detail);
    await expect(page.getByRole('button', { name: 'Run onboarding' })).toBeEnabled();
    await expect(page.locator('#run-meta')).toContainText('run ' + previous.runId.slice(0, 8));
    await expect(page.getByLabel('Recent runs')).toHaveValue(previous.runId);
    await page.unroute('**/api/runs');
  });
});
