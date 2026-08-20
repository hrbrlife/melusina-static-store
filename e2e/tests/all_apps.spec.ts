import { test, expect, request } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { EXPECTED_APPS } from '../fixtures/expected_apps';

/* Per-app integration: for every app in the catalog, confirm
 *  - the actual card icon source returns 200 (signed app icon or Bazaar mark)
 *  - the SPK package URL returns 200
 *  - RELEASE.json returns 200 and matches the catalog ReleaseEntry summary
 *  - every public-facing app's detail modal opens, version + author show up
 *
 * Foundation, operator, and engineering pearls remain release-verifiable but
 * deliberately do not have normal Bazaar cards. Their absence is an explicit
 * safety property, not a missing catalog row.
 */

const STORE = process.env.STORE_BASE_URL
  ?? 'https://bazaar.melusina-os.org/';
const norm = (s: string) => s.replace(/\/+$/, '');
const STORE_NORM = norm(STORE);

// Keep this assertion aligned with the source's generated signed icon map
// without importing the Vite ESM module through Playwright's CommonJS loader.
const iconMapSource = readFileSync(new URL('../../src/app-icon-map.js', import.meta.url), 'utf8');
const appIconPaths = new Map(
  [...iconMapSource.matchAll(/^  "([a-z0-9]{52})": "(\/icons\/apps\/[^\"]+)",$/gm)]
    .map(([, appId, iconPath]) => [appId, iconPath]),
);
const bazaarMarkIconPath = iconMapSource.match(
  /BAZAAR_MARK_ICON_PATH = "([^\"]+)"/,
)?.[1];
if (!bazaarMarkIconPath) {
  throw new Error('generated Bazaar mark icon path is missing');
}

let catalog: any[] = [];
type InstallationPolicy = {
  audience: string;
  install_mode: string;
  pearl_role: string;
  client_access: string;
  admin_surface: string;
};

const checkedInInstallationPolicy = JSON.parse(readFileSync(
  new URL('../../sidecar/melusina-store-sidecar/ui/installation-policy.json', import.meta.url),
  'utf8',
)) as Record<string, InstallationPolicy>;
let installationPolicy: Record<string, InstallationPolicy> = {};

const loadCatalog = async () => {
  const ctx = await request.newContext();
  try {
    let lastStatus = 0;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const res = await ctx.get(`${STORE_NORM}/apps/index.json`);
      lastStatus = res.status();
      if (res.ok()) {
        const data = await res.json();
        return data.apps;
      }
      if (attempt < 2) {
        await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
      }
    }
    throw new Error(`apps/index.json must load (final HTTP ${lastStatus})`);
  } finally {
    await ctx.dispose();
  }
};

const loadInstallationPolicy = async () => {
  const ctx = await request.newContext();
  try {
    const res = await ctx.get(`${STORE_NORM}/installation-policy.json`);
    expect(res.status(), 'installation policy must load').toBe(200);
    return await res.json() as Record<string, InstallationPolicy>;
  } finally {
    await ctx.dispose();
  }
};

const isVisibleInPublicBazaar = (entry: any) => {
  const audience = installationPolicy[entry.appId]?.audience;
  return audience === 'client' || audience === 'workspace';
};

test.beforeAll(async () => {
  [catalog, installationPolicy] = await Promise.all([loadCatalog(), loadInstallationPolicy()]);
  expect(catalog.length, 'catalog must contain apps').toBeGreaterThan(0);
  expect(Object.keys(installationPolicy).sort(), 'policy must cover every catalog app')
    .toEqual(catalog.map((app) => app.appId).sort());
});

test('Catalog matches expected app set', async () => {
  const got = catalog.map(a => a.name).sort();
  const want = EXPECTED_APPS.map(a => a.name).sort();
  expect(got).toEqual(want);
});

test('Every app release uses the same 3-of-4 publishing authority', async () => {
  const authorityFor = (entry: any) => {
    const attest = entry.attest;
    expect(attest, `${entry.name} must include an attestation summary`).toBeDefined();
    expect(attest.quorumPolicy?.threshold).toBe(3);
    expect(attest.quorumPolicy?.memberCount).toBe(4);
    expect(attest.licenseSquadsVault).toBeTruthy();
    expect(attest.quorumPolicy?.multisigPda).toBeTruthy();

    // SPK/app author signatures deliberately vary by app. The Squads vault and
    // complete public quorum policy must not: there are no app-level exceptions.
    return {
      licenseSquadsVault: attest.licenseSquadsVault,
      quorumPolicy: attest.quorumPolicy,
    };
  };

  const sharedAuthority = authorityFor(catalog[0]);
  for (const entry of catalog) {
    expect(authorityFor(entry), `${entry.name} publishing authority`).toEqual(sharedAuthority);
  }
});

test('Live installation policy matches the checked-in signed policy', async () => {
  expect(installationPolicy).toEqual(checkedInInstallationPolicy);
});

test('Public Bazaar exposes exactly the policy-visible app cards', async ({ page }) => {
  await page.goto('');
  const visibleApps = catalog.filter(isVisibleInPublicBazaar);
  await expect(page.getByText(`${visibleApps.length} apps`, { exact: true })).toBeVisible();

  for (const entry of catalog) {
    const heading = page.locator(`h3:text-is("${entry.name}")`);
    await expect(heading, `${entry.name} public card visibility`)
      .toHaveCount(isVisibleInPublicBazaar(entry) ? 1 : 0);
  }
});

for (const app of EXPECTED_APPS) {
  test.describe(`App: ${app.name}`, () => {
    test('icon, SPK, ReleaseEntry attestation all return 200', async ({ request }) => {
      const entry = catalog.find(a => a.name === app.name);
      expect(entry, `${app.name} not in catalog`).toBeDefined();
      // The UI intentionally does not trust mutable catalog imageId fields.
      // It uses a signed appId-keyed icon map, falling back to the Bazaar mark
      // for explicitly iconless or not-yet-mapped apps.
      const iconPath = appIconPaths.get(entry.appId) ?? bazaarMarkIconPath;
      const iconRes = await request.get(`${STORE_NORM}${iconPath}`);
      expect(iconRes.status(),
        `rendered icon ${iconPath} for ${entry.name} must be 200`).toBe(200);
      // SPK (may be on Releases for >95MB apps; we only check the local /packages/ path)
      if (!entry.packageUrl) {
        const spkRes = await request.head(`${STORE_NORM}/packages/${entry.packageId}`);
        expect(spkRes.status(),
          `SPK ${entry.packageId} must be 200`).toBe(200);
      }
      // ReleaseEntry-backed attestation manifest
      expect(entry.attest, `${entry.name} must include attest summary`).toBeDefined();
      expect(entry.attest.appHash).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.attest.releaseHash).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.attest.releaseEntryPda).toBeTruthy();
      expect(entry.attest.masterNftMint).toBeTruthy();
      expect(entry.attest.licenseSquadsVault).toBeTruthy();
      expect(entry.attest.quorumPolicy?.threshold).toBe(3);
      expect(entry.attest.quorumPolicy?.memberCount).toBe(4);
      expect(entry.attest.signedAtUnix).toBeGreaterThan(0);

      const releaseRes = await request.get(
        `${STORE_NORM}/attest/${entry.appId}/RELEASE.json`);
      expect(releaseRes.status(),
        `RELEASE.json for ${entry.appId} must be 200`).toBe(200);
      const release = await releaseRes.json();
      expect(release.$schema).toBe('melusina-release-v1');
      expect(release.appHash).toBe(entry.attest.appHash);
      expect(release.releaseHash).toBe(entry.attest.releaseHash);
      expect(release.releaseEntryPda).toBe(entry.attest.releaseEntryPda);
      expect(release.masterNftMint).toBe(entry.attest.masterNftMint);
      expect(release.licenseSquadsVault).toBe(entry.attest.licenseSquadsVault);
      expect(release.quorumPolicy).toEqual(entry.attest.quorumPolicy);
      expect(release.signedAtUnix).toBe(entry.attest.signedAtUnix);
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
      const entry = catalog.find(a => a.name === app.name);
      expect(entry, `${app.name} not in catalog`).toBeDefined();
      test.skip(!isVisibleInPublicBazaar(entry),
        'Foundation, operator, and engineering pearls intentionally have no public Bazaar card.');
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
      // FAQ is a rendered per-app surface and must remain reachable.
      await page.getByRole('button', { name: /FAQ/i }).first().click();
    });
  });
}
