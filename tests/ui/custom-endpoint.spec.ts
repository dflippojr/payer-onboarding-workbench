import { expect, type Route } from '@playwright/test';
import { ready, test } from './fixtures';
import { customEndpointForm } from './custom-endpoint-form';

test.use({ expectedErrors: [/\b400\b/] });

test('custom selection hides synthetic faults and submits connection edits', async ({ page }) => {
  await customEndpointForm(page);
});

// #298: the server may have custom endpoints on, so an unanswered feature check must not claim otherwise.
test.describe('when the feature check fails', () => {
  test.use({ expectedErrors: [/\b503\b|Failed to load resource/] });

  for (const [name, answer] of [
    ['answers 503', (route: Route) => route.fulfill({ status: 503, json: { error: 'unavailable' } })],
    ['is refused', (route: Route) => route.abort()],
  ] as const) {
    test(`the banner makes no synthetic-only claim when it ${name}`, async ({ page }) => {
      await ready(page);
      await page.route('**/api/features', answer);
      await page.reload();
      await expect(page.getByRole('radio')).toHaveCount(3);
      await expect(page.locator('body')).not.toContainText(/no real payer|synthetic payers only/i);
      await expect(page.getByRole('note')).toContainText('does not by itself establish interoperability');
    });
  }
});
