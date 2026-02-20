# Melusina App Bazaar — Publish Quality Control

Generic checklist for verifying any app before publishing to the Melusina App Bazaar.
Every item must pass before an SPK is accepted into the store.

---

## 1. Build Pipeline (`make build`)

- [ ] `make build` completes without errors
- [ ] All grain binaries are compiled and placed in the correct output directory (`pearls/`, `grain/`, or project root)
- [ ] Binary is statically linked or all required shared libraries are accounted for
- [ ] Embedded assets (templates, static files) are bundled into the binary or placed alongside it
- [ ] No stale build artifacts from previous versions remain
- [ ] Build is reproducible — clean checkout + `make build` produces a working result

---

## 2. Development Mode (`make dev`)

- [ ] `make dev` unmounts any existing mount, mounts `/opt/app`, and runs `spk dev`
- [ ] No build steps run inside `make dev` — it uses pre-built artifacts only
- [ ] App launches and is functional in development grain
- [ ] Grain types all instantiate correctly in dev mode
- [ ] Hot-reload or re-mount works without restarting the grain

---

## 3. Packaging (`make pack`)

- [ ] `make pack` runs `spk pack` only — no `make build` or `make dev` step
- [ ] SPK file is produced successfully
- [ ] `spk verify <file.spk>` passes with no errors
- [ ] `alwaysInclude` in `sandstorm-pkgdef.capnp` is comprehensive — the dynamically-generated `sandstorm-files.list` is not required
- [ ] SPK installs cleanly on a fresh Sandstorm instance
- [ ] All grain types launch and function after install from SPK

---

## 4. alwaysInclude & System Dependencies

- [ ] `alwaysInclude` explicitly lists every app binary/artifact
- [ ] `alwaysInclude` includes `sandstorm-manifest`
- [ ] `alwaysInclude` includes launcher script (if applicable)
- [ ] System symlinks included: `bin`, `lib`, `lib64` (for apps using bash/coreutils)
- [ ] Required coreutils included: `usr/bin/bash`, `usr/bin/cat`, `usr/bin/mkdir`, etc.
- [ ] All shared libraries listed: `lib/x86_64-linux-gnu/libc.so.6`, `libpthread`, `libtinfo`, `libselinux`, `libpcre2`, `ld-linux-x86-64.so.2`, etc.
- [ ] Timezone data included: `etc/localtime`, `usr/share/zoneinfo/<zone>`
- [ ] For Python/Node apps: interpreter, stdlib, `dist-packages`, SSL certs all included
- [ ] `alwaysInclude` entries cross-checked against `sourceMap.searchPath` — paths resolve correctly
- [ ] No extraneous entries that bloat the package unnecessarily

---

## 5. App Size

- [ ] SPK size is reasonable for the app type:
  - Go binary (embed.FS): **5–25 MB**
  - Go + static assets: **15–40 MB**
  - Python/Node apps: **80–200 MB**
- [ ] No accidental inclusion of build tools, test fixtures, `.git/`, `node_modules/`, or dev dependencies
- [ ] Large assets (fonts, images) are justified and optimized

---

## 6. CDN & Bundling

- [ ] **Zero CDN references** in any shipped HTML, JS, or CSS
- [ ] No `<script src="https://...">` or `<link href="https://...">` tags pointing to external hosts
- [ ] Specifically verify none of these appear in shipped templates:
  - `unpkg.com`
  - `cdn.jsdelivr.net`
  - `cdnjs.cloudflare.com`
  - `fonts.googleapis.com`
  - `fonts.gstatic.com`
  - `cdn.tailwindcss.com`
- [ ] All vendor libraries present locally in `static/vendor/` or equivalent
- [ ] Google Fonts (if used) are self-hosted as `.woff2` files with local `@font-face` declarations
- [ ] MathJax / KaTeX (if used) loaded from local bundle, not CDN
- [ ] Makefile `vendor` target (if present) downloads pinned versions, `make build` depends on it

---

## 7. Publisher Signature & Keys

- [ ] SPK is signed with the correct GPG key for the publisher
- [ ] Signing key identity matches the app author declared in the store listing
- [ ] Key fingerprint is documented and consistent across all published apps
- [ ] PGP signature file (`.sandstorm/pgp-signature` or equivalent) is present and committed
- [ ] `pgpSignature` field in capnp references the correct signature file
- [ ] Key is backed up securely (not only on one machine)
- [ ] Key expiry date is checked — not expired or expiring imminently
- [ ] Test: `spk verify <file.spk>` validates the signature successfully
- [ ] Publisher name, email, and key ID are consistent between:
  - GPG keyring
  - `sandstorm-pkgdef.capnp` metadata
  - Store listing (`apps.json`)

---

## 8. Store Listing Metadata (`apps.json`)

Every app entry must have all fields populated and accurate:

- [ ] `appId` — unique, matches the value in `sandstorm-pkgdef.capnp`
- [ ] `packageId` — matches the built SPK's package ID
- [ ] `name` — human-readable app name
- [ ] `version` — semver string matching capnp `appVersion`
- [ ] `versionNumber` — integer, incremented from previous release
- [ ] `shortDescription` — concise one-liner (≤100 chars)
- [ ] `description` — full markdown description covering features, grain types, and technical details
- [ ] `categories` — correct and properly cased:
  - Valid values: `productivity`, `office`, `social`, `developerTools`, `communications`, `finance`, `media`, `games`, `other`
  - Cross-check: categories make sense for what the app actually does
- [ ] `screenshots` — at least 3 screenshots with captions:
  - [ ] Screenshots exist in `packages/<app>/screenshots/` directory
  - [ ] Image files are PNG, reasonable resolution (1280×800 or similar)
  - [ ] Captions are descriptive, not just "screenshot1"
  - [ ] Screenshots show real usage, not placeholder/blank states
- [ ] `imageId` — app icon is present and referenced correctly (SVG preferred)
- [ ] `author.name` — real author name
- [ ] `author.githubUsername` — correct GitHub username
- [ ] `webLink` — valid URL, publicly accessible
- [ ] `codeLink` — valid URL pointing to source repository
- [ ] `upstreamAuthor` — correct attribution
- [ ] `isOpenSource` — accurate (matches actual license)
- [ ] `createdAt` — valid timestamp (milliseconds since epoch)
- [ ] `packageUrl` — if present, points to a valid downloadable SPK (for non-sideload installs)

---

## 9. Licensing

- [ ] License file exists in the repository (`LICENSE`, `LICENSE.md`, or `COPYING`)
- [ ] License type is declared and matches `isOpenSource` field in store listing
- [ ] If open source: license is OSI-approved (MIT, Apache-2.0, GPL, etc.)
- [ ] If proprietary: `isOpenSource` is `false` and no open-source license file is present
- [ ] Third-party dependencies' licenses are compatible with the app's license
- [ ] Vendor/bundled libraries include their license notices where required (MIT, BSD require attribution)
- [ ] License hasn't changed between versions without explicit notice

---

## 10. Pricing & Distribution

- [ ] Pricing model is declared (free, paid, donation-ware)
- [ ] If paid: payment flow is documented and functional
- [ ] Distribution channel is correct — publishing to **Melusina App Bazaar only**, NOT to the upstream Sandstorm app market
- [ ] `make publish` target pushes to the correct repository and branch
- [ ] No accidental `spk publish` to `app-index.sandstorm.io` in any Makefile

---

## 11. capnp Package Definition

- [ ] `sandstorm-pkgdef.capnp` is well-formed and parseable
- [ ] `appTitle` matches store listing name
- [ ] `appVersion` matches store listing version number
- [ ] `appMarketingVersion` matches store listing version string
- [ ] All declared grain types (`actions`) have correct:
  - `title` — user-visible grain name
  - `nounPhrase` — correct grammar ("a spreadsheet", "an inbox")
  - `command` — correct binary/script path and args
- [ ] `continueCommand` is valid — references a defined command, not an undefined constant
- [ ] `sourceMap.searchPath` is correct — app files resolve from repo, system files from `/`
- [ ] `metadata` fields are populated:
  - `icons` (appGrid, grain, market, appMarket)
  - `website`
  - `codeUrl`
  - `license` (openSource or proprietary)
  - `categories`
  - `author`
  - `pgpSignature`
  - `description`
  - `shortDescription`
  - `screenshots`
  - `changeLog`

---

## 12. Final Verification

- [ ] Clean clone → `make vendor` (if applicable) → `make build` → `make pack` → install SPK → all grains work
- [ ] `spk verify <file.spk>` passes
- [ ] Store page renders correctly after `make publish` in static_store
- [ ] App icon displays properly in the Bazaar grid
- [ ] App detail page shows description, screenshots, metadata
- [ ] Download/install link (if present) points to valid SPK
- [ ] No regressions from previous published version
