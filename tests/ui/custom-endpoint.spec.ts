import { test } from './fixtures';
import { customEndpointForm } from './custom-endpoint-form';

test.use({ expectedErrors: [/\b400\b/] });

test('custom selection hides synthetic faults and submits connection edits', async ({ page }) => {
  await customEndpointForm(page);
});
