import { test, expect, request } from '@playwright/test';

/* Admin app-market view. ADMIN_BASE_URL is mandatory and supplied only by
 * the governed clean-tenant test environment. */

const ADMIN = process.env.ADMIN_BASE_URL!;
const STORE = process.env.STORE_BASE_URL ?? 'https://bazaar.melusina-os.org';

test.beforeAll(async () => {
  const ctx = await request.newContext({ timeout: 10_000, ignoreHTTPSErrors: true });
  const res = await ctx.get(ADMIN, { timeout: 10_000 });
  expect(res.status(), `governed tenant must respond at ${ADMIN}`).toBeLessThan(500);
});

test.describe('Admin app market', () => {
  test('Admin page responds', async ({ page }) => {
    const resp = await page.goto(ADMIN);
    expect(resp).not.toBeNull();
    // Not a 5xx; auth gates (401/403) or login redirects (200/302) are fine.
    expect(resp!.status()).toBeLessThan(500);
  });

  test('Page has a recognisable Sandstorm shell', async ({ page }) => {
    await page.goto(ADMIN);
    // Sandstorm shells include sidebar / topbar / login form / app grid.
    // Loose check: page contains the word Sandstorm OR Melusina OR has an app grid root.
    const html = await page.content();
    const matches = /sandstorm|melusina|app.?grid/i.test(html);
    expect(matches, 'admin shell should mention Sandstorm or Melusina').toBe(true);
  });

  test('Admin endpoint serves at least one of our installable packages', async ({ request, page }) => {
    // Pick the first app's packageId from the public catalog and check the
    // admin "install by URL" flow accepts it (just resolves status, no real install).
    const ctx = await request.newContext();
    const cat = await (await ctx.get(`${STORE.replace(/\/+$/, '')}/apps/index.json`)).json();
    const app = cat.apps[0];
    const installUrl = new URL(`/install/${app.packageId}`, ADMIN);
    installUrl.searchParams.set('url', `${STORE.replace(/\/+$/, '')}/packages/${app.packageId}`);
    const resp = await page.goto(installUrl.toString(), { waitUntil: 'domcontentloaded' });
    expect(resp).not.toBeNull();
    expect(resp!.status()).toBeLessThan(500);
  });
});
