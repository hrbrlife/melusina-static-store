import { defineConfig, devices } from '@playwright/test';

/* Modeled on the DueProcess (AITX-Procedures) e2e harness:
 *   - timeout 120s, expect 30s
 *   - retries 1, list reporter, on-failure trace/video
 *   - projects per audience (here: store-public + store-mobile + admin)
 *
 * Two layers under test:
 *   STORE_BASE_URL  — the default Bazaar (default: bazaar.melusina-os.org)
 *   ADMIN_BASE_URL  — a Melusina/Sandstorm admin app market (optional;
 *                     skipped automatically if unreachable)
 */
const STORE_BASE_URL = process.env.STORE_BASE_URL
  ?? 'https://bazaar.melusina-os.org/';
// Sandstorm admin app URL for E2E install-loop tests.
// REQUIRED: Set ADMIN_BASE_URL to a Melusina/Sandstorm admin app market URL.
// No default — fail closed so misconfigured CI runs fail immediately.
const ADMIN_BASE_URL = process.env.ADMIN_BASE_URL;
if (!ADMIN_BASE_URL) {
  throw new Error('ADMIN_BASE_URL is required. Set it to a Sandstorm admin app market URL.');
}
const CHROMIUM_EXECUTABLE = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;

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
    ...(CHROMIUM_EXECUTABLE
      ? { launchOptions: { executablePath: CHROMIUM_EXECUTABLE } }
      : {}),
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: process.env.PLAYWRIGHT_CAPTURE_VIDEO === '1' ? 'retain-on-failure' : 'off',
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
        browserName: 'chromium',
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
