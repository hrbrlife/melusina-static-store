import { defineConfig, devices } from '@playwright/test';

/* Modeled on the DueProcess (AITX-Procedures) e2e harness:
 *   - timeout 120s, expect 30s
 *   - retries 1, list reporter, on-failure trace/video
 *   - projects per audience (here: store-public + store-mobile + admin)
 *
 * Two layers under test:
 *   STORE_BASE_URL  — the public bazaar (default: live GitHub Pages deployment)
 *   ADMIN_BASE_URL  — a Melusina/Sandstorm admin app market (optional;
 *                     skipped automatically if unreachable)
 */
const STORE_BASE_URL = process.env.STORE_BASE_URL
  ?? 'https://hrbrlife.github.io/melusina-static-store/';
const ADMIN_BASE_URL = process.env.ADMIN_BASE_URL
  ?? 'https://dev.melusina-os.org/apps';

export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  expect: { timeout: 30_000 },
  fullyParallel: false,
  retries: process.env.CI ? 2 : 1,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]],
  outputDir: 'test-results',
  use: {
    ignoreHTTPSErrors: true,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'store-public',
      testMatch: /static_store\.spec\.ts/,
      use: {
        baseURL: STORE_BASE_URL,
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: 'store-mobile',
      testMatch: /static_store_mobile\.spec\.ts/,
      use: {
        baseURL: STORE_BASE_URL,
        ...devices['iPhone 14'],
      },
    },
    {
      name: 'admin',
      testMatch: /admin_store\.spec\.ts/,
      use: {
        baseURL: ADMIN_BASE_URL,
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: 'all-apps',
      testMatch: /all_apps\.spec\.ts/,
      use: {
        baseURL: STORE_BASE_URL,
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 900 },
      },
    },
  ],
});
