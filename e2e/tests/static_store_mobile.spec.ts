import { test, expect } from '@playwright/test';
import { TOTAL_APPS } from '../fixtures/expected_apps';

/* Mobile (iPhone 14) viewport — confirm responsive layout doesn't drop
 * critical surfaces. */

test.describe('Static store — mobile viewport', () => {
  test('Catalog still renders', async ({ page }) => {
    await page.goto('');
    await expect(page.getByText(new RegExp(`${TOTAL_APPS}\\s*apps?`)).first())
      .toBeVisible();
  });

  test('Search input stays accessible', async ({ page }) => {
    await page.goto('');
    await expect(page.getByPlaceholder('search_apps...')).toBeVisible();
  });

  test('Sticky install bar appears on detail page', async ({ page }) => {
    await page.goto('');
    await page.getByRole('heading').filter({ hasText: /^[A-Z]/ }).first().click();
    // The mobile install bar is fixed at bottom under 768px viewport.
    // Look for an INSTALL button visible on viewport.
    const installBtn = page.getByRole('button', { name: /↓\s*INSTALL/i }).first();
    await expect(installBtn).toBeVisible();
  });
});
