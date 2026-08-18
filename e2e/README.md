# Melusina static_store e2e tests

Playwright suite covering the public bazaar, the per-app integration
contract (icon + SPK + ReleaseEntry attestation all reachable), the mobile
viewport, and (optionally) the Sandstorm admin app market.

Modeled on the DueProcess (`AITX-Procedures/e2e/`) harness.

## Run

```sh
cd e2e
npm install
npx playwright install --with-deps chromium firefox
npm test                       # full suite
npx playwright test --project=store-public
npx playwright test --project=all-apps
npx playwright test --project=store-mobile
npx playwright test --project=admin
```

## Environment

```
STORE_BASE_URL  default: https://bazaar.melusina-os.org/
ADMIN_BASE_URL  default: https://dev.melusina-os.org/apps
```

The `admin` project auto-skips if `ADMIN_BASE_URL` isn't reachable.

## Suite layout

| Spec                          | Project        | What it asserts |
|-------------------------------|----------------|-----------------|
| `static_store.spec.ts`        | store-public   | landing renders, 21 apps, search/category filters work, detail modal opens, install modal opens, service worker registers, no console errors, no community surfaces |
| `all_apps.spec.ts`            | all-apps       | for every expected app: icon URL 200, SPK URL 200, `/attest/<appId>/RELEASE.json` URL 200 and matching catalog ReleaseEntry summary; detail modal opens; version + categories match catalog |
| `static_store_mobile.spec.ts` | store-mobile   | catalog renders on iPhone 14, search accessible, sticky install bar appears |
| `admin_store.spec.ts`         | admin          | admin page reachable, Sandstorm shell present, install URL resolves |

## Updating the expected catalog

`fixtures/expected_apps.ts` is the source of truth for what should ship.
After adding/removing an app, update this list and run `npm test`.
