import { test, expect, ready, runOnboarding, openDrawer } from './fixtures';

for (const state of ['initial', 'results']) {
  test('primary page ' + state + ' has no horizontal overflow at required breakpoints', async ({ page }) => {
    await ready(page);
    if (state === 'results') {
      await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
      await runOnboarding(page);
      await page.getByText('Step details', { exact: true }).first().click();
    }
    for (const width of [320, 375, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      await page.evaluate(() => document.fonts.ready);
      await expect.poll(() => page.evaluate(() => window.innerWidth)).toBe(width);
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    }
  });
}

test('editable fields and complete touch targets stay usable through phone reflow', async ({ page }, testInfo) => {
  await ready(page);
  await page.getByLabel('Sample request').selectOption('order-sign-hospital-bed');
  await runOnboarding(page);
  await page.getByText('Step details', { exact: true }).first().click();
  await openDrawer(page, 'Payer faults');
  await openDrawer(page, 'Connection overrides');
  await page.locator('#clientId').fill('synthetic-resize');
  await page.locator('#clientId').focus();

  for (const viewport of [
    { width: 320, height: 900 }, { width: 375, height: 667 },
    { width: 667, height: 375 }, { width: 768, height: 1024 },
    { width: 1440, height: 900 },
  ]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => page.evaluate(() => window.innerWidth)).toBe(viewport.width);
    await expect(page.locator('#clientId')).toHaveValue('synthetic-resize');
    await expect(page.locator('#clientId')).toBeFocused();
    const measurements = await page.evaluate(() => {
      const fields = [...document.querySelectorAll<HTMLElement>('input:not([type="radio"]):not([type="checkbox"]), select, textarea')]
        .filter(element => element.getClientRects().length > 0);
      const targets = [...document.querySelectorAll<HTMLElement>('.pick, .check, button, a.button, summary')]
        .filter(element => element.getClientRects().length > 0);
      const faults = [...document.querySelectorAll('.check')].map(element => element.getBoundingClientRect());
      const gaps: number[] = [];
      for (let i = 0; i < faults.length; i++) for (let j = i + 1; j < faults.length; j++) {
        const a = faults[i], b = faults[j];
        if (a.left < b.right && b.left < a.right && b.top >= a.bottom) gaps.push(b.top - a.bottom);
      }
      return {
        fonts: fields.map(element => ({ id: element.id, size: parseFloat(getComputedStyle(element).fontSize) })),
        sizes: [...fields, ...targets].map(element => {
          const rect = element.getBoundingClientRect();
          return { id: element.id || element.className || element.tagName, width: rect.width, height: rect.height };
        }),
        gaps,
        overflow: document.documentElement.scrollWidth > window.innerWidth,
        focusOutline: getComputedStyle(document.activeElement!).outlineStyle,
      };
    });
    expect(measurements.overflow).toBe(false);
    for (const font of measurements.fonts) expect(font.size, font.id).toBeGreaterThanOrEqual(16);
    for (const size of measurements.sizes) {
      expect(size.width, size.id).toBeGreaterThanOrEqual(44);
      expect(size.height, size.id).toBeGreaterThanOrEqual(44);
    }
    expect(measurements.gaps.length).toBeGreaterThan(0);
    for (const gap of measurements.gaps) expect(gap).toBeGreaterThanOrEqual(8);
    expect(measurements.focusOutline).not.toBe('none');
    await page.getByRole('button', { name: 'Reset faults and settings' }).scrollIntoViewIfNeeded();
    await expect(page.getByRole('button', { name: 'Reset faults and settings' })).toBeInViewport();
    if (viewport.width === 375) {
      await testInfo.attach('phone-reflow', { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });
    }
  }
  await page.getByRole('button', { name: 'Reset faults and settings' }).click();
  await expect(page.locator('#clientId')).toHaveValue('');
});

test('workspace puts setup beside the results on desktop, with Run in the first screen', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await ready(page);
  const setup = page.getByRole('form', { name: 'Run setup' });
  const results = page.getByRole('heading', { name: 'Steps', exact: true });
  const [left, right] = [await setup.boundingBox(), await results.boundingBox()];
  expect(Math.round(left!.width)).toBe(380);
  expect(right!.x).toBeGreaterThan(left!.x + left!.width);
  await expect(page.locator('details.drawer[open]')).toHaveCount(0);
  await expect(page.locator('#faults-state')).toHaveText('None on');
  await expect(page.locator('#overrides-state')).toHaveText('Stored settings');
  await expect(page.getByRole('button', { name: 'Run onboarding' })).toBeInViewport({ ratio: 1 });
  await expect(page.locator('#pending-steps li')).toHaveCount(6);

  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => window.innerWidth)).toBe(390);
  const [stackedSetup, stackedResults] = [await setup.boundingBox(), await results.boundingBox()];
  expect(stackedResults!.y).toBeGreaterThan(stackedSetup!.y + stackedSetup!.height);
  expect(stackedSetup!.x).toBe(16);
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
