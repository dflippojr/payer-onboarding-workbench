import { test, expect, type Page, type TestInfo } from '@playwright/test';
import { copyFile, mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ready, runOnboarding, reopen, auditEvent, openDrawer } from '../../../../tests/ui/fixtures';

import { customEndpointForm } from '../../../../tests/ui/custom-endpoint-form';

// One test per feature in the SKILL.md feature map; the tag is the feature name drive.mjs greps for.
const evidence = process.env.VERIFY_EVIDENCE!;
const PAYER = 'northwind-synthetic';
const SAMPLE = 'order-sign-hospital-bed';

async function shot(page: Page, info: TestInfo, name: string) {
  await mkdir(join(evidence, 'screenshots'), { recursive: true });
  await page.screenshot({ path: join(evidence, 'screenshots', info.project.name + '-' + name + '.png'), fullPage: true });
}

// Choose the synthetic payer and sample with faults and settings cleared, as the contract's journeys do.
async function choose(page: Page) {
  await ready(page);
  await page.locator('input[value="' + PAYER + '"]').check();
  await page.getByRole('combobox', { name: 'Environment', exact: true }).selectOption('SANDBOX');
  await page.getByLabel('Sample request').selectOption(SAMPLE);
  await page.getByRole('button', { name: 'Reset faults and settings' }).click();
  await expect(page.locator('input[name="fault"]:checked')).toHaveCount(0);
}

async function failingRun(page: Page) {
  await choose(page);
  await openDrawer(page, 'Payer faults');
  await page.getByRole('checkbox', { name: 'Discovery is down' }).check();
  const result = await runOnboarding(page);
  await expect(page.locator('#verdict-word')).toHaveText('Fail · broke at Discovery');
  return result;
}

test('healthy discovery and sample request @healthy', async ({ page }, info) => {
  await choose(page);
  const result = await runOnboarding(page);
  await expect(page.locator('#run-status')).toHaveText('Done: no failures.');
  await expect(page.locator('#steps .failed')).toHaveCount(0);
  await expect(page.locator('#steps .step h3')).toContainText(['Discovery', 'Send sample hook request']);
  await auditEvent('run.completed', result.runId, { payerId: PAYER, environment: 'SANDBOX', sampleId: SAMPLE });
  await shot(page, info, 'healthy');
});

test('failure explanation for an injected fault @failure', async ({ page }, info) => {
  const result = await failingRun(page);
  // The verdict card names the first failing check with its Fix and evidence.
  const finding = page.locator('#verdict-check');
  await expect(finding).toContainText('discovery.reachable');
  await expect(finding.locator('.fix')).toBeVisible();
  await finding.locator('summary').first().click();
  await expect(finding.locator('details[open]').first()).toBeVisible();
  await auditEvent('run.completed', result.runId, { payerId: PAYER, environment: 'SANDBOX', sampleId: SAMPLE });
  await shot(page, info, 'failure');
});

test('diagnostic report for the failed run @report', async ({ page }, info) => {
  const result = await failingRun(page);
  await reopen(page, result.runId);
  await page.getByLabel('Report format').selectOption('html');
  const pending = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Download report' }).click();
  const file = (await (await pending).path())!;
  const report = await readFile(file, 'utf8');
  expect(report).toContain(result.runId);
  expect(report).toContain('FAIL');
  expect(report.toLowerCase()).toContain('synthetic');
  await auditEvent('report.rendered', result.runId, { reportFormat: 'html' });
  await mkdir(join(evidence, 'reports'), { recursive: true });
  await copyFile(file, join(evidence, 'reports', info.project.name + '-' + result.runId + '.html'));
  await shot(page, info, 'report');
});

test('inject a fault, then reset it @reset', async ({ page }, info) => {
  await choose(page);
  await openDrawer(page, 'Payer faults');
  await page.getByRole('checkbox', { name: 'Discovery is down' }).check();
  await openDrawer(page, 'Connection overrides');
  await page.locator('#igVersion').fill('2.0.1');
  await page.getByRole('button', { name: 'Reset faults and settings' }).click();
  await expect(page.locator('input[name="fault"]:checked')).toHaveCount(0);
  await expect(page.locator('#igVersion')).toHaveValue('');
  await runOnboarding(page);
  await expect(page.locator('#run-status')).toHaveText('Done: no failures.');
  await shot(page, info, 'reset');
});

test('running state while a run is in flight @running', async ({ page }, info) => {
  await choose(page);
  await runOnboarding(page);
  await openDrawer(page, 'Payer faults');
  await page.getByRole('checkbox', { name: 'Payer is slow' }).check();
  // Hold the POST while the page is checked, then send it without the slow fault so the drive stays quick.
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/api/runs', async route => {
    if (route.request().method() !== 'POST') return route.continue();
    await held;
    await route.continue({ postData: JSON.stringify({ ...route.request().postDataJSON(), faults: [] }) });
  });
  await page.getByRole('button', { name: 'Run onboarding' }).click();
  await expect(page.locator('.results')).toHaveAttribute('aria-busy', 'true');
  await expect(page.locator('#verdict-word')).toHaveText('Running');
  await expect(page.locator('#run-meta')).toContainText('about 11 s');
  await expect(page.locator('#running-steps .step.pending')).toHaveCount(6);
  await expect(page.locator('#steps-card')).toBeHidden();
  await shot(page, info, 'running');
  release();
  await expect(page.locator('#run-status')).toHaveText('Done: no failures.');
  await expect(page.locator('.results')).not.toHaveAttribute('aria-busy');
  await expect(page.locator('#steps > li').first()).toBeVisible();
  await page.unroute('**/api/runs');
});

test('compare a failing run with a healthy one, then stop comparing @compare', async ({ page }, info) => {
  await choose(page);
  const healthy = await runOnboarding(page);
  await failingRun(page);
  const compare = page.getByLabel('Compare with');
  await compare.selectOption(healthy.runId);
  const comparison = page.getByRole('region', { name: 'Changes since run ' + healthy.runId.slice(0, 8) });
  await expect(comparison.locator('.tile dd').first()).toHaveText('Pass → Fail Worse');
  await expect(comparison.getByRole('row', { name: /discovery\.reachable/ })).toContainText('Newly failing');
  await expect(comparison.locator('details.one-sided')).not.toHaveAttribute('open', '');
  await auditEvent('run.read', healthy.runId);
  await comparison.scrollIntoViewIfNeeded();
  await shot(page, info, 'compare');
  await page.getByRole('button', { name: 'Stop comparing' }).click();
  await expect(comparison).toBeHidden();
  await expect(compare).toBeFocused();
});

test('custom form hides faults and retains connection edits @custom', async ({ page }, info) => {
  await customEndpointForm(page, () => shot(page, info, 'custom'));
});

// Not a feature: a deliberate failure used by cleanup.test.mjs to prove cleanup after a failed drive.
test('deliberate drive failure @selftest-fail', async ({ page }) => {
  await ready(page);
  expect(false, 'deliberate drive failure (selftest-fail)').toBe(true);
});
