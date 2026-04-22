import { test, expect, request } from '@playwright/test';
import { EXPECTED_APPS } from '../fixtures/expected_apps';

/* Per-app integration: for every app in the catalog, confirm
 *  - the card icon image returns 200 (not a 404 → letter fallback)
 *  - the SPK package URL returns 200
 *  - the metadata signature URL returns 200 (trust kernel)
 *  - the detail modal opens, version + author show up
 */

const STORE = process.env.STORE_BASE_URL
  ?? 'https://hrbrlife.github.io/melusina-static-store/';
const norm = (s: string) => s.replace(/\/+$/, '');
const STORE_NORM = norm(STORE);

let catalog: any[] = [];

test.beforeAll(async () => {
  const ctx = await request.newContext();
  const res = await ctx.get(`${STORE_NORM}/apps/index.json`);
  expect(res.status(), 'apps/index.json must load').toBe(200);
  const data = await res.json();
  catalog = data.apps;
  expect(catalog.length, 'catalog must contain apps').toBeGreaterThan(0);
});

test('Catalog matches expected app set', async () => {
  const got = catalog.map(a => a.name).sort();
  const want = EXPECTED_APPS.map(a => a.name).sort();
  expect(got).toEqual(want);
});

for (const app of EXPECTED_APPS) {
  test.describe(`App: ${app.name}`, () => {
    test('icon, SPK, signature all return 200', async ({ request }) => {
      const entry = catalog.find(a => a.name === app.name);
      expect(entry, `${app.name} not in catalog`).toBeDefined();
      // Icon
      const iconRes = await request.get(`${STORE_NORM}/images/${entry.imageId}`);
      expect(iconRes.status(),
        `icon ${entry.imageId} must be 200`).toBe(200);
      // SPK (may be on Releases for >95MB apps; we only check the local /packages/ path)
      if (!entry.packageUrl) {
        const spkRes = await request.head(`${STORE_NORM}/packages/${entry.packageId}`);
        expect(spkRes.status(),
          `SPK ${entry.packageId} must be 200`).toBe(200);
      }
      // Signature
      const sigRes = await request.head(
        `${STORE_NORM}/signatures/${entry.appId}/metadata.json.asc`);
      expect(sigRes.status(),
        `signature for ${entry.appId} must be 200`).toBe(200);
    });

    test('catalog entry has expected version + categories', async () => {
      const entry = catalog.find(a => a.name === app.name);
      expect(entry).toBeDefined();
      expect(entry.version).toBe(app.version);
      // Each expected category must appear (catalog may have additional).
      for (const c of app.categories) {
        const titleCase = c.charAt(0).toUpperCase() + c.slice(1).toLowerCase();
        expect(entry.categories.map((x: string) => x.toLowerCase()))
          .toContain(c.toLowerCase());
      }
    });

    test('detail modal opens', async ({ page }) => {
      await page.goto('');
      await expect(page.getByText(/\d+\s*apps?/).first()).toBeVisible();
      // Find the h3 for this app, walk to the parent card image, click.
      const heading = page.locator(`h3:text-is("${app.name}")`).first();
      await heading.scrollIntoViewIfNeeded();
      await heading.click({ force: true });
      await expect(page.getByRole('button', { name: /←\s*BACK/i })).toBeVisible();
      // Hero shows app name as h1.
      await expect(page.getByRole('heading', { level: 1, name: app.name }))
                       .toBeVisible();
      // Versions tab is reachable.
      await page.getByRole('button', { name: /Versions/i }).first().click();
    });
  });
}
