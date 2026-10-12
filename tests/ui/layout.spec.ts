import { test, expect, ready, runOnboarding } from './fixtures';

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
