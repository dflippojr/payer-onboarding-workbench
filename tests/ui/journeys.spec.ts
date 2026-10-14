import { readFile } from 'node:fs/promises';
import { test, expect, ready, runOnboarding, reopen, audit, auditEvent, openDrawer } from './fixtures';

for (const payer of ['northwind', 'fabrikam', 'tailspin']) {
  test('J01/J05/J06 healthy ' + payer + ', reload, history and reports', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await ready(page);
    await page.locator('input[value="' + payer + '-synthetic"]').check();
    await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
    const result = await runOnboarding(page);
    await expect(page.locator('#run-status')).toHaveText('Done: no failures.');
    await expect(page.locator('#steps .failed')).toHaveCount(0);
    await expect(page.locator('#verdict-word')).toHaveText(/^Pass/);
    await expect(page.locator('#results-heading')).toHaveText(/^Every step passed/);
    await expect(page.locator('#verdict-check')).toBeHidden();
    // Passing checks stay collapsed.
    await expect(page.locator('#findings .group.PASS details')).not.toHaveAttribute('open', '');
    await audit('run.completed', result.runId, payer + '-synthetic');
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
}

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
  await compare.focus();
  await compare.selectOption(healthy.runId);
  await expect(page.locator('#history-status')).toHaveText('Comparison shown.');
  const comparison = page.getByRole('region', { name: 'Changes since run ' + healthy.runId.slice(0, 8) });
  await expect(comparison).toBeVisible();
  await expect(comparison.locator('dd').first()).toContainText('PASS → FAIL worse');
  await expect(comparison.locator('dd').nth(1)).toHaveText('every step passed → Discovery');
  await expect(comparison.getByRole('heading', { name: /^Newly failing or worse/ }).locator('xpath=following-sibling::ul[1]'))
    .toContainText('discovery.reachable');
  await auditEvent('run.read', healthy.runId);
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByLabel('Recent runs').selectOption(healthy.runId);
  await expect(comparison).toBeHidden();
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
