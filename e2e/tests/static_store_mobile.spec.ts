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
    // h3 headings are the catalog cards; do not accidentally select the Bazaar
    // title, which would leave us on the catalog page.
    await page.locator('h3').first().click();

    // The mobile install bar is fixed at the viewport bottom under 768px.
    const mobileInstallBar = page.locator('.mobile-sticky-install');
    await expect(mobileInstallBar).toBeVisible();
    await expect(mobileInstallBar.getByRole('button', { name: /↓\s*INSTALL/i }))
      .toBeVisible();
  });
});
