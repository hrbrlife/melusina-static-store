import { test, expect } from '@playwright/test';
import { EXPECTED_APPS, TOTAL_APPS } from '../fixtures/expected_apps';

/* Top-level static-store flow:
 *  - landing renders
 *  - 21 apps appear (not 0, not 22)
 *  - search narrows results
 *  - category pills filter results
 *  - first-app detail modal opens cleanly
 *  - install modal opens and lists pbay servers
 *  - service-worker registers
 *  - no console errors above warnings
 */

test.describe('Static store — public surface', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('');
    // Wait for the catalog grid to be populated. The count text is split
    // across spans, so look for the literal "apps" word with a number nearby.
    await expect(page.getByText(/\d+\s*apps?/).first()).toBeVisible();
  });

  test('Landing renders header + catalog', async ({ page }) => {
    await expect(page).toHaveTitle(/Melusina/i);
    await expect(page.getByText('MELUSINA', { exact: true }).first()).toBeVisible();
    await expect(page.getByText('APP BAZAAR', { exact: true })).toBeVisible();
    await expect(page.getByPlaceholder('search_apps...')).toBeVisible();
    await expect(page.getByRole('button', { name: /GET MELUSINA/i })).toBeVisible();
  });

  test(`Exactly ${TOTAL_APPS} apps render`, async ({ page }) => {
    // The count is rendered as <span>21</span> apps — assert the number
    // appears near the literal word "apps".
    const countText = page.getByText(new RegExp(`${TOTAL_APPS}\\s*apps?`)).first();
    await expect(countText).toBeVisible();
  });

  test('Every expected app name appears at least once', async ({ page }) => {
    for (const app of EXPECTED_APPS) {
      // App names appear in their card heading; loose match to allow
      // surrounding markup.
      await expect(page.getByRole('heading', { name: app.name, exact: true })
                       .first()).toBeVisible();
    }
  });

  test('Category filters narrow results', async ({ page }) => {
    // OFFICE pill exists for Bureau-suite apps. Click it.
    await page.getByRole('button', { name: /^OFFICE$/i }).click();
    // After filtering, fewer cards. Verify number is < TOTAL.
    const headings = page.locator('h3');
    const filteredCount = await headings.count();
    expect(filteredCount).toBeGreaterThan(0);
    expect(filteredCount).toBeLessThan(TOTAL_APPS);
    // Reset
    await page.getByRole('button', { name: /^ALL$/i }).click();
    const allCount = await headings.count();
    expect(allCount).toBeGreaterThanOrEqual(TOTAL_APPS);
  });

  test('Search narrows results', async ({ page }) => {
    await page.getByPlaceholder('search_apps...').fill('bureau');
    // Bureau-suite quartet + Notes/Cal/Contacts → at least 5 hits.
    const filtered = page.getByText(/\d+\s*apps?/).first();
    await expect(filtered).toBeVisible();
    const txt = await filtered.innerText();
    const m = txt.match(/(\d+)/);
    const n = parseInt(m![1]);
    expect(n).toBeGreaterThanOrEqual(5);
    expect(n).toBeLessThan(TOTAL_APPS);
    await page.getByPlaceholder('search_apps...').fill('');
  });

  test('Detail modal opens for first app', async ({ page }) => {
    // Capture any JS errors during navigation
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => {
      if (m.type() === 'error') errors.push(m.text());
    });

    const firstCardImage = page.locator('img[alt=""]').first();
    await firstCardImage.scrollIntoViewIfNeeded();
    await firstCardImage.click({ force: true });

    // If nav failed, surface the error rather than time out silently.
    try {
      await expect(page.getByRole('button', { name: /←\s*BACK|^BACK/i }))
        .toBeVisible({ timeout: 15000 });
    } catch (e) {
      const url = page.url();
      throw new Error(
        `Detail page didn't render. URL=${url}\n` +
        `Errors during click:\n${errors.join('\n') || '(none captured)'}`
      );
    }
    // The Overview tab shows.
    await expect(page.getByRole('button', { name: 'Overview', exact: true })
                     .first()).toBeVisible();
    await expect(page.getByRole('button', { name: /Versions/i })
                     .first()).toBeVisible();
    await expect(page.getByRole('button', { name: /FAQ/i })
                     .first()).toBeVisible();
    await page.getByRole('button', { name: /BACK/i }).click();
  });

  test('Install modal opens with pbay/private toggle', async ({ page }) => {
    const firstCardImage = page.locator('img[alt=""]').first();
    await firstCardImage.scrollIntoViewIfNeeded();
    await firstCardImage.click({ force: true });
    await expect(page.getByRole('button', { name: /←\s*BACK|^BACK/i }))
      .toBeVisible({ timeout: 15000 });
    // Click the detail-page INSTALL button.
    const installBtn = page.getByRole('button', { name: /INSTALL/i }).last();
    await installBtn.scrollIntoViewIfNeeded();
    await installBtn.click({ force: true });
    // Install modal lists both pbay AND Private Servers as toggle tabs.
    await expect(page.getByRole('button', { name: /pbay\.app/i })).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('button', { name: /Private Servers/i })).toBeVisible();
    await page.keyboard.press('Escape');
  });

  test('Service worker registers', async ({ page }) => {
    const swRegs = await page.evaluate(async () => {
      if (!('serviceWorker' in navigator)) return [];
      const regs = await navigator.serviceWorker.getRegistrations();
      return regs.map(r => r.scope);
    });
    expect(swRegs.length).toBeGreaterThan(0);
    expect(swRegs.some(s => s.includes('melusina-static-store'))).toBe(true);
  });

  test('No deferred-tools community surfaces visible', async ({ page }) => {
    // We removed Reviews/Bug Reports/Feature Requests/Ideas — none of
    // those tabs/buttons should exist anywhere on the page.
    const banned = ['Reviews', 'Bug Reports', 'Feature Requests', 'Ideas'];
    for (const word of banned) {
      // The text might appear inside a description, but not as a tab/button.
      const buttons = page.getByRole('button', { name: new RegExp(`^${word}\\s*\\(?`, 'i') });
      await expect(buttons).toHaveCount(0);
    }
  });

  test('No console errors during page load', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') errors.push(msg.text());
    });
    await page.reload();
    await expect(page.getByText(/\d+\s*apps?/).first()).toBeVisible();
    const real = errors.filter(e => !/(favicon|robots|sourcemap)/i.test(e));
    expect(real, `unexpected console errors:\n${real.join('\n')}`).toEqual([]);
  });
});
