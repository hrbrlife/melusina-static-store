import { test, expect, request } from '@playwright/test';
import { TOTAL_APPS } from '../fixtures/expected_apps';

/* Admin store / Sandstorm app market view — optional.
 *
 * If the configured ADMIN_BASE_URL isn't reachable (no Melusina dev server,
 * no auth, etc.), every test in this file SKIPS rather than fails. This
 * keeps CI green when the only thing under test is the public store.
 */

const ADMIN = process.env.ADMIN_BASE_URL ?? 'https://dev.melusina-os.org/apps';

let adminReachable = false;

test.beforeAll(async () => {
  try {
    const ctx = await request.newContext({ timeout: 5000, ignoreHTTPSErrors: true });
    const res = await ctx.get(ADMIN, { timeout: 5000 });
    adminReachable = res.ok() || res.status() === 401 || res.status() === 302;
  } catch {
    adminReachable = false;
  }
});

test.describe('Admin app market', () => {
  test.beforeEach(async () => {
    test.skip(!adminReachable, `admin store not reachable at ${ADMIN}`);
  });

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
    const cat = await (await ctx.get('https://hrbrlife.github.io/melusina-static_store/apps/index.json')).json();
    const app = cat.apps[0];
    const installUrl = new URL(`/install/${app.packageId}`, ADMIN);
    installUrl.searchParams.set('url', `https://hrbrlife.github.io/melusina-static_store/packages/${app.packageId}`);
    const resp = await page.goto(installUrl.toString(), { waitUntil: 'domcontentloaded' });
    expect(resp).not.toBeNull();
    expect(resp!.status()).toBeLessThan(500);
  });
});
