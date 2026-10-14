import type { APIRequestContext, Locator, Page } from '@playwright/test';
import { test, expect } from './fixtures';

// The HTML report is rendered in a real browser from a real run's report. Print breaks, dark mode and the
// side-by-side request and response only mean something in a browser, so the Java tests no longer match markup
// strings for them. The spec sets viewport, colour scheme and media itself, so it runs once per engine.
test.beforeEach(({}, testInfo) => {
  test.skip(!['desktop-light', 'phone-light'].includes(testInfo.project.name), 'viewport and colour scheme are set by the test');
});

const DESKTOP = { width: 1440, height: 900 };
const PHONE = { width: 390, height: 844 };

/** Runs Northwind (with Discovery down, or healthy) and shows its HTML report as a page. */
async function openReport(page: Page, request: APIRequestContext, failing: boolean) {
  const run = await request.post('/api/runs', { data: {
    payerId: 'northwind-synthetic', environment: 'SANDBOX', sampleId: 'order-sign-hospital-bed',
    faults: failing ? ['discovery-500'] : [],
  } });
  expect(run.ok()).toBe(true);
  const { runId } = await run.json();
  const report = await request.get('/api/runs/' + runId + '/report?format=html');
  expect(report.ok()).toBe(true);
  await page.setViewportSize(DESKTOP);
  await page.emulateMedia({ colorScheme: 'light', media: 'screen' });
  await page.setContent(await report.text());
  return runId as string;
}

const box = async (locator: Locator) => (await locator.boundingBox())!;

/** The request and response columns of the failing call. */
const exchange = (page: Page) => ({
  request: page.getByText('Request headers', { exact: true }).locator('..'),
  response: page.getByText('Response headers', { exact: true }).locator('..'),
});

const luminance = (color: string) => {
  const [r, g, b] = color.match(/\d+(\.\d+)?/g)!.map(Number);
  return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
};
const background = (page: Page) => page.evaluate(() => getComputedStyle(document.body).backgroundColor);

test('the report leads with the verdict icon, word and where the run broke', async ({ page, request }) => {
  await openReport(page, request, true);
  const verdict = page.getByRole('region', { name: 'Verdict: Fail' });
  await expect(verdict.getByRole('heading', { name: 'Verdict: Fail' })).toBeVisible();
  await expect(verdict.locator('svg[aria-hidden="true"]').first()).toBeVisible();
  await expect(verdict.getByText('Broke at Discovery', { exact: true })).toBeVisible();
  await expect(verdict.getByText('1 fail')).toBeVisible();
  // The verdict comes before the facts about the run.
  expect((await box(verdict)).y).toBeLessThan((await box(page.getByText('Payer', { exact: true }))).y);
});

test('a healthy report says Pass and does not say where it broke', async ({ page, request }) => {
  await openReport(page, request, false);
  await expect(page.getByRole('heading', { name: 'Verdict: Pass' })).toBeVisible();
  await expect(page.getByText('Broke at')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Failing call' })).toHaveCount(0);
});

test('the failing call puts curl before the request and response, side by side on a wide screen', async ({ page, request }) => {
  await openReport(page, request, true);
  const heading = page.getByRole('heading', { name: 'Failing call' });
  const curl = page.getByText('Reproduce with curl', { exact: true });
  const { request: sent, response: received } = exchange(page);
  expect((await box(heading)).y).toBeLessThan((await box(curl)).y);
  expect((await box(curl)).y).toBeLessThan((await box(sent)).y);
  const chip = page.getByText('HTTP 500', { exact: true });
  await expect(chip).toBeVisible();
  await expect(chip.locator('xpath=following-sibling::span[1]')).toHaveText(/^\d+ ms$/);

  // Side by side on a wide screen: one top edge, request on the left.
  expect(Math.round((await box(sent)).y)).toBe(Math.round((await box(received)).y));
  expect((await box(sent)).x).toBeLessThan((await box(received)).x);

  // Stacked on a phone, and on paper.
  await page.setViewportSize(PHONE);
  let top = await box(sent);
  expect((await box(received)).y).toBeGreaterThanOrEqual(top.y + top.height);
  await page.setViewportSize(DESKTOP);
  await page.emulateMedia({ media: 'print' });
  top = await box(sent);
  expect((await box(received)).y).toBeGreaterThanOrEqual(top.y + top.height);
});

test('dark mode is for screens only, and print keeps headings with their block', async ({ page, request }) => {
  await openReport(page, request, true);
  await page.emulateMedia({ colorScheme: 'dark', media: 'screen' });
  expect(luminance(await background(page))).toBeLessThan(0.2);
  await page.emulateMedia({ colorScheme: 'dark', media: 'print' });
  expect(luminance(await background(page))).toBeGreaterThan(0.95);

  const breaks = (locator: Locator, property: 'breakAfter' | 'breakInside') =>
    locator.evaluate((element, name) => getComputedStyle(element)[name], property);
  for (const heading of [page.getByRole('heading', { level: 2 }).first(), page.getByRole('heading', { level: 3 }).first()]) {
    expect(await breaks(heading, 'breakAfter')).toBe('avoid');
  }
  expect(await breaks(page.getByText('Reproduce with curl', { exact: true }).locator('xpath=../pre'), 'breakInside')).toBe('avoid');
  expect(await breaks(page.locator('footer'), 'breakInside')).toBe('avoid');

  // Cards are outlined evenly: none leans on a coloured left border.
  for (const card of await page.getByRole('article').all()) {
    const border = await card.evaluate(element => {
      const style = getComputedStyle(element);
      return { left: style.borderLeftColor, top: style.borderTopColor };
    });
    expect(border.left).toBe(border.top);
  }
});

test('every step and finding has a word beside its icon', async ({ page, request }) => {
  await openReport(page, request, true);
  const steps = page.getByRole('region', { name: 'Step timeline' }).getByRole('listitem');
  await expect(steps).toHaveCount(6);
  for (const step of await steps.all()) {
    await expect(step.getByText(/^(passed|failed|skipped)$/)).toBeVisible();
  }
  const findings = page.getByRole('article');
  expect(await findings.count()).toBeGreaterThan(0);
  for (const finding of await findings.all()) {
    const word = finding.getByText(/^(Fail|Warn|Pass)$/);
    await expect(word).toBeVisible();
    // The word comes before the finding's heading in reading order.
    const heading = await finding.getByRole('heading', { level: 3 }).elementHandle();
    expect(await word.evaluate((element, other) => !!(element.compareDocumentPosition(other!) & Node.DOCUMENT_POSITION_FOLLOWING), heading)).toBe(true);
  }
});
