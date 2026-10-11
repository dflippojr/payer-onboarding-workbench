import { readFile } from 'node:fs/promises';
import { test, expect, ready, runOnboarding, reopen, audit, auditEvent } from './fixtures';

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
    await audit('run.completed', result.runId, payer + '-synthetic');
    await reopen(page, result.runId);
    await auditEvent('run.read', result.runId);
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
  await page.getByRole('checkbox', { name: 'Discovery is down' }).check();
  const failed = await runOnboarding(page);
  await expect(page.locator('#run-meta')).toContainText('broke at: Discovery');
  await expect(page.locator('.finding.FAIL')).toContainText('discovery.reachable');
  await expect(page.locator('.finding.FAIL .fix').first()).toBeVisible();
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
  await expect(page.locator('#steps .step.skipped')).toHaveCount(3);
  const evidence = page.locator('.finding.FAIL summary').first();
  await evidence.press('Enter');
  await expect(page.locator('.finding.FAIL details[open]').first()).toBeVisible();
  await page.locator('#baseUrlSuffix').fill('/r4');
  await page.locator('#igVersion').fill('2.0.1');
  await page.locator('#clientId').fill('synthetic-edit');
  await page.getByRole('button', { name: 'Reset faults and settings' }).click();
  for (const id of ['baseUrlSuffix', 'igVersion', 'clientId']) await expect(page.locator('#' + id)).toHaveValue('');
  await expect(page.locator('input[name="fault"]:checked')).toHaveCount(0);
  await runOnboarding(page);
  await expect(page.locator('#run-status')).toHaveText('Done: no failures.');
});

test('J04 unavailable environment produces retained diagnostic run', async ({ page }) => {
  await ready(page);
  await page.getByRole('combobox', { name: 'Environment', exact: true }).selectOption('STAGING');
  const result = await runOnboarding(page);
  await expect(page.locator('#run-meta')).toContainText('broke at: Resolve connection');
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
  await page.getByRole('checkbox', { name: 'Discovery is down' }).focus();
  await page.keyboard.press('Space');
  await expect(page.getByRole('checkbox', { name: 'Discovery is down' })).toBeChecked();
  await page.getByRole('button', { name: 'Reset faults and settings' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('input[name="fault"]:checked')).toHaveCount(0);
  await page.getByRole('button', { name: 'Run onboarding' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#run-status')).toContainText('Done:');
  await expect(page.getByRole('heading', { name: 'Steps', exact: true })).toBeFocused();
  // Exercise link activation/focus independently of the browser's native traversal preference.
  await page.getByRole('link', { name: 'Skip to results' }).focus();
  await expect(page.getByRole('link', { name: 'Skip to results' })).toBeInViewport();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Steps', exact: true })).toBeFocused();
});

test('J08 connection edit belongs to one retained run and has matching audit metadata', async ({ page }) => {
  await ready(page);
  await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
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
  await expect(page.locator('.finding.FAIL').filter({ hasText: 'response.coverage-information' })).toHaveCount(1);
});
