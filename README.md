# Melusina Static Store

Static app store and update host for Melusina. Hosted on GitHub Pages from the `publish` branch.

**Live store**: https://hrbrlife.github.io/melusina-static-store/

> **This checkout is a development mirror, not the canonical builder.**
> Two `static_store` checkouts exist on this host with non-overlapping
> app sets (this one has the bureau / cca.sh-Client / NamedCoin lane;
> `Melusina/static_store/` has Telescreen Configuration / BLOOM / Shell
> Tester). The live `gh-pages` catalog has 29 apps; this checkout has
> 25; neither local checkout reproduces the live set on its own.
> `make deploy` is therefore hard-gated on `MELUSINA_PUBLISH_AUTHORITATIVE=1`
> and `scripts/preflight.sh` aborts on `.spk`-hash drift against the
> Melusina deployer approval-manifest by default. See [`POSTMORTEM.md`](POSTMORTEM.md)
> (gh-pages 2026-04-25 catalog-shrink regression) for context and
> [`docs/M1_CCASH_CONFIG_PUBLISH_PATH.md`](docs/M1_CCASH_CONFIG_PUBLISH_PATH.md)
> for the publication procedure when ccash kill-list task **A1** lands
> the admin-grain v0.1.0.

---

## Publish the store

```
make publish
```

That's it. One command. It does everything:

1. Pulls latest from all app submodules (their `publish` branches)
2. Runs `build-store.sh` (scans metadata, builds Vite frontend, assembles `dist-publish/`)
3. Copies the Melusina server binary update (`update/sandstorm-0.tar.xz`, filename retained for updater compatibility) into the output
4. Splits any files over 95MB into 90MB chunks (GitHub Pages limit)
5. Commits and pushes `main`
6. Deploys everything to the `publish` branch
7. Switches back to `main`

You must be on the `main` branch. Nothing else required.

---

## Publish an individual app

Every app repo has the same standardized Makefile. From any app repo:

```bash
# Build and test locally
make build && make dev

# Pack a release (auto-bumps version, creates .spk, verifies)
make pack

# Pack + push to the app's publish branch
make publish
```

Then come back here and run `make publish` to deploy the store.

### Full workflow (app change → live store)

```bash
# 1. In the app repo — make your changes, then:
make publish

# 2. In this repo (static_store):
make publish
```

Done. The store picks up the new version automatically.

---

## App repos

Each app is a git submodule under `packages/hrbrlife/`, tracking that repo's `publish` branch. Inspect `.gitmodules` for the live list of registered submodules; see [`PUBLISH_READINESS.md`](PUBLISH_READINESS.md) for the per-app status matrix (currently 25 apps published, plus a few unregistered plain-tree paths the catalog tracks directly).

Each app's `publish` branch contains the slug-shaped tree `{slug}/app.spk`, `{slug}/metadata.json`, `{slug}/RELEASE.json`, `{slug}/icon.svg` (or `.png`), `{slug}/description.md`, `{slug}/screenshots/`. `RELEASE.json` is mandatory and the only trust root: the store validates it against the on-chain Solana `ReleaseEntry` via `melusina-pearl-tool verify-release` before publishing. Legacy detached PGP signatures (`metadata.json.asc`) are explicitly rejected at `build-store.sh:352` — zero PGP surface anywhere in pack/publish post-Janeway 2026-04-23.

---

## Adding a new app

1. Create the app repo with the standardized Makefile (copy the existing SPK Makefile template from any current app)
2. Run `make publish` in the app repo to create its `publish` branch
3. Add the submodule here:
   ```bash
   git submodule add -b publish https://github.com/hrbrlife/NEW_APP.git packages/hrbrlife/NEW_APP
   ```
4. Run `make publish` here

---

## Melusina binary update

The file `update/sandstorm-0.tar.xz` is the Melusina server binary. It gets deployed to `publish` alongside the store. Do not regenerate or modify it unless you're shipping a new server build.

---

## Publish env vars

The build resolves a few external dependencies via env vars. Set what's relevant for your host.

| Var | Default | Purpose |
|-----|---------|---------|
| `MELUSINA_RELEASE_VERIFY_TOOL` / `PEARL_TOOL` | `melusina-pearl-tool` (PATH) | Path to the `melusina-pearl-tool` binary used by `validate_release_attestation` to verify each `RELEASE.json` against its on-chain `ReleaseEntry`. Build fails hard if the tool is missing and verification is not skipped. |
| `MELUSINA_ATTEST_OFFLINE` | unset | Set to `1` to skip the on-chain RPC lookup (still enforces the local `RELEASE.json` schema + finalization fields). Use on air-gapped publishers or when a public RPC is unavailable. |
| `MELUSINA_SKIP_BUNDLE_UPDATE` | unset | Set to `1` to skip the entire Sandstorm bundle-update block (catalog ships, no `update/sandstorm-N.tar.xz.update-sig` produced). Required when the publisher does not have access to the bundle-update keyring (`$SANDSTORM_SRC/keys/melusina-update-keyring`); default is fail-hard so an unsigned bundle never ships. |
| `MELUSINA_PUBLISH_AUTHORITATIVE` | unset | **Hard gate.** Required to be `1` for `make deploy` to proceed. Default-unset aborts deploy with a pointer to `docs/M1_CCASH_CONFIG_PUBLISH_PATH.md` and `POSTMORTEM.md` follow-up #1. Two `static_store` checkouts share the same upstream on this host with non-overlapping app sets; this flag is the explicit declaration that this checkout is the canonical publisher. |
| `MELUSINA_PUBLISH_SHRINK_OK` | unset | `scripts/preflight.sh` Gate 1 (live-catalog diff) aborts when the local build would drop appIds present in live `gh-pages`. Set to `1` only when shrink is *intentional* (e.g. an app retirement coordinated in chat). |
| `MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT` | unset | `scripts/preflight.sh` Gate 2 (manifest cross-check) **fails by default** when local `.spk` SHA-256 diverges from the deployer manifest's expected `app_hash`. Set to `1` only when reseat work is in flight on Worf's side and acknowledged in chat — drift means the catalog would serve bytes that no longer match the on-chain `ReleaseEntry` and installs would fail signature verification. |

## Trust model

Every app in this catalog is gated by a Solana on-chain `ReleaseEntry` and a Squads-multisig signature. There are no PGP keys, no detached metadata signatures, no out-of-band approvals. End-user verification recipe is documented at [`verifier/index.html`](verifier/index.html) (deployed to `https://hrbrlife.github.io/melusina-static-store/verifier/`); the per-app published `attest` block in `apps.json` carries everything needed to re-check the chain independently of trusting this static site.

---

## Repo structure

```
static_store/
├── Makefile               # make publish — refresh + build + commit + deploy
├── build-store.sh         # Validates RELEASE.json against on-chain ReleaseEntry, builds frontend, assembles dist-publish/
├── PUBLISH_QC.md          # Per-app publish QC checklist
├── PUBLISH_READINESS.md   # Per-app current status matrix + submodule registration scope
├── src/
│   ├── main.jsx           # Store frontend (React)
│   └── apps.json          # Generated app index (do not edit — built by build-store.sh)
├── packages/hrbrlife/     # App submodules (publish branches) + a few plain-tree paths
│   └── ... (25 apps, see PUBLISH_READINESS.md)
├── update/
│   └── sandstorm-0.tar.xz # server binary (do not touch — see "Publish env vars" below)
├── verifier/
│   └── index.html         # Independent-verifier doc page (Solana ReleaseEntry trust model + CLI recipe)
└── dist-publish/          # Build output (deployed to publish branch)
    ├── apps/              # Generated catalog index
    ├── attest/            # Per-app RELEASE.json manifests by appId
    ├── signatures/        # Per-app metadata.json copies for re-validation
    ├── verifier/          # Static verifier page
    └── packages/          # SPKs keyed by packageId
```

## Branches

- **`main`** — Source code, submodule refs, server binary (LFS). Push here for development.
- **`publish`** — GitHub Pages deployment. Raw files only, no LFS. Never edit directly — `make publish` manages it.
