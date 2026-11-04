import { test, expect, ready } from './fixtures';

// #306: a run timed out in ready() on "Loading payers…" and nothing recorded which request the page was waiting for.
test('a startup that never finishes names the call with no answer', async ({ page }) => {
  await page.route('**/api/samples', () => {});
  const error = await ready(page, 500).then(() => null, (e: Error) => e);
  expect(error?.message).toMatch(/No answer: GET \/api\/samples \(\d+ ms\)/);
  expect(error?.message).toMatch(/Answered: .*GET \/api\/payers \(\d+ ms\)/);
  expect(error?.message).toMatch(/Host load: \d/);
});

test.describe('a script that fails to load', () => {
  test.use({ expectedErrors: [/./] });
  test('leaves the same page, and the report names the script', async ({ page }) => {
    await page.route('**/compare.js', route => route.abort());
    const error = await ready(page, 500).then(() => null, (e: Error) => e);
    expect(error?.message).toMatch(/Failed: GET \/compare\.js/);
    await expect(page.locator('#payers')).toContainText('Loading payers');
  });
});
