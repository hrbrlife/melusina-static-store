# M1 — `cca.sh Config` (admin pearl) catalog publication path

> **Status:** closed loop as of 2026-04-26 — `cca.sh Config` v0.0.1
> is live in the catalog (`packages/hrbrlife/melusina_ccashconfig_app/
> cca-sh-config/`), kill-list tasks **A1+A2** are GREEN (see §1
> footnotes). The procedure below is the operator runbook for
> subsequent re-publishes (v0.2.0, v0.3.0, …) once the admin pearl
> ships the next signed `.spk`. The §1 pre-conditions still gate
> every release.

> **Owner:** static_store agent. Read together with
> `/home/user/Desktop/ccash_go_htmx/docs/MVP_INTEGRATION_KILL_LIST_FINAL.md`
> §4.4 (admin pearl state) and §5.A (admin task list A1–A7).

---

## 0. Identity (locked)

| Field | Value |
|---|---|
| App display name | `cca.sh Config` |
| AppId | `6gdgveudrer5a61hp8qkmxcn89wyce5uq1mg92ud40ugr2uj7mz0` |
| Source repo (working) | `/home/user/Desktop/melusina_ccashconfig_app/` |
| Upstream | `hrbrlife/melusina_ccashconfig_app` (confirmed; plain-tree-in-catalog rather than submodule per `PUBLISH_READINESS.md` §"Off-catalog") |
| Catalog slot | `packages/hrbrlife/melusina_ccashconfig_app/cca-sh-config/` |
| Approval manifest entry | `Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json` — name `cca.sh Config`, expected `app_hash` `d0fd938fac00...` |
| Trust root | Solana `ReleaseEntry` + Squads multisig (no PGP, per Captain Janeway 2026-04-23 — `metadata.json.asc` is rejected at `build-store.sh:352`). Signing is gated through the offline-wallet / Squads path per Charter HT13 — no hot-key fallback for any on-chain release tx. |

The AppId is pinned. Do not mint a new one; do not change it across releases. The Sandstorm install ID is what the user's pearl Grapple-claims.

---

## 1. Pre-conditions (must be true before this procedure runs)

These are the upstream gates owned by other agents. Static_store does not advance until all five are green.

1. **A1 done** — `melusina_ccashconfig_app/main.go` is no longer the 55-LOC welcome-page stub. A real Cap'n Proto `AdminGate_Server` is wired in front of `pkg/registry`, `pkg/router`, `pkg/broker`, `pkg/manifest`. Source: kill-list §5.A row A1. *(Status 2026-04-25 end-of-day: GREEN. Admin pearl ships AdminGate via raw Cap'n Proto on FD 3 — the http-bridge `/admin/cases` + `/admin/spawn` endpoints from the earlier A1 status snapshot were deleted in commit `c5e0055` along with launcher.sh + templates/index.html. Operator interaction is now Grapple-claim-only; the admin pearl has zero browser UI by design.)*
2. **A2 done** — `sandstorm-pkgdef.capnp` exports the `AdminGate` offerable. Without this, ccash Grapple cannot claim it. Source: kill-list §5.A row A2. *(Status 2026-04-25 end-of-day: GREEN — landed at melusina_ccashconfig_app `c5e0055`. Path (a) of the architectural call surfaced in chat idx 96/102/109/117: switched the admin pearl from sandstorm-http-bridge to in-process raw-capnp UiView, mirroring cyberteller + AITX Procedures. Peer ccash grains claim AdminGate via `NewSession(sessionType=AdminGate_TypeID)` on FD 3. `bridgeConfig` block deleted from sandstorm-pkgdef; runCommand argv is `["/ccashconfig"]` — no http-bridge wrap.)*
3. **A3–A5 done** — manifest allowlist wired (§1.5 invariant), `getFlowTemplate` reads YAML from `ccash_domain_template/domains/popaye/stations/*.yaml`. *(A4 amendment 2026-04-25: the original `DEV_MODE=1` env-var-gated re-read was superseded by mtime-aware cache invalidation in `melusina_ccashconfig_app/pkg/server/template_provider.go` — commit `a0ec71c`. Captain Imperative on top of A4 (FINAL kill-list §1.13 amendment / §3.4 superseded): ccash refreshes from admin on every `requireXTemplate` call (`ccash_go_htmx@356edec`), so combined with the admin's mtime-aware cache, **a YAML edit shows up on the next ccash request — no admin restart, no ccash restart**. The catalog metadata.json contract is unaffected; this footnote exists so a future reader doesn't chase a `DEV_MODE` flag that doesn't exist or assume restarts are required.)*
4. **`make pack` builds a working `.spk`** — version `0.1.0`, run from `/home/user/Desktop/melusina_ccashconfig_app/` per the standard SPK Makefile (`make build && make pack` produces `cca-sh-config.spk`).
5. **`RELEASE.json` produced and on-chain attested** — `melusina-pearl-tool` mints a `ReleaseEntry` with the admin operator's Squads multisig; the resulting `RELEASE.json` carries `appId`, `version`, `versionNumber`, `packageId` (sha256 of `.spk`), `releaseEntry` (Solana PDA address), and `signature` (Squads tx). The packageId hex must match the deployer manifest's `app_hash` for `cca.sh Config` (`d0fd938f...`); if it doesn't, **stop and route to Worf for reseat or rebuild — do not advance**.

If any of (1)–(5) is not green, `cca.sh Config` stays absent from local catalog. The kill-list M1 milestone (handshake alive) does **not** depend on this catalog entry — ccash's Grapple claim resolves against the live Sandstorm install of the admin pearl, not against gh-pages.

---

## 2. Procedure (when (1)–(5) are green)

### 2.1 Stage the catalog directory

Two cases:

**Case A — upstream `hrbrlife/melusina_ccashconfig_app` repo exists with a `publish` branch.**
The publish branch must carry the slug-shaped tree `cca-sh-config/{app.spk, metadata.json, RELEASE.json, icon.svg, description.md, screenshots/}`.

```bash
cd /home/user/Desktop/static_store
git submodule add -b publish \
  https://github.com/hrbrlife/melusina_ccashconfig_app.git \
  packages/hrbrlife/melusina_ccashconfig_app
```

**Case B — no upstream `publish` branch yet.**
Mirror the `Fineract-setup` pattern (per `PUBLISH_READINESS.md` §"Submodule registration scope" lines 220–234): keep as a plain-tree-in-catalog. The admin-pearl agent re-packages into the catalog directly each release; no submodule registration.

The standard SPK Makefile (`make pack` from the working repo) produces a slug-shaped *directory* `cca-sh-config/` next to its sibling artifacts, with `app.spk` inside it. The catalog expects exactly the same shape — copy it over verbatim:

```bash
SRC=/home/user/Desktop/melusina_ccashconfig_app
DST=/home/user/Desktop/static_store/packages/hrbrlife/melusina_ccashconfig_app

# Make the parent directory; the slug-shaped subdir 'cca-sh-config/' is what
# build-store.sh will scan for app.spk + metadata.json + RELEASE.json.
mkdir -p "$DST"
cp -a "$SRC/cca-sh-config" "$DST/"

# Required files inside $DST/cca-sh-config/ after the copy:
#   app.spk            — the binary package
#   metadata.json      — appId, version, versionNumber, packageId
#   RELEASE.json       — Solana ReleaseEntry attestation payload
#   icon.svg or .png   — store thumbnail
#   description.md     — long-form description
#   screenshots/       — optional, if present
# If `make pack` deposits app.spk somewhere other than cca-sh-config/app.spk,
# the working repo's Makefile is not following the standard SPK template —
# fix the Makefile, don't paper over it here.
```

Either way (Case A submodule pointer or Case B plain-tree copy), the resulting tree shape under `packages/hrbrlife/melusina_ccashconfig_app/cca-sh-config/` is the same — `build-store.sh` doesn't care whether the path is a submodule or a plain directory.

### 2.2 Verify

From the static_store root:

```bash
make build
MELUSINA_PUBLISH_AUTHORITATIVE=1 \
  bash scripts/preflight.sh
```

What to look for:
- Gate 1 (live-catalog diff): `cca.sh Config` already in live (29 apps); after this stage it appears in local too. No `REMOVED` line for it. If the rest of the live set is still missing, the diff still shows REMOVED for those — that's `POSTMORTEM` follow-up #1, not this procedure's blocker.
- Gate 2 (manifest cross-check): `cca.sh Config` no longer in the "missing local .spk" list; the local hash matches `d0fd938f...`. If it doesn't, **stop**. The .spk and `RELEASE.json` must agree with the on-chain attest before any deploy can ship this entry.
- Gate 3 (authoritative-host): warns unless `MELUSINA_PUBLISH_AUTHORITATIVE=1`. The Makefile `deploy` target hard-aborts if the var isn't set; preflight is informational.

If preflight aborts (`exit 1`): fix the surfaced issue, re-run. Do not override gates with `MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1` unless reseat work is in flight on Worf's side and acknowledged in chat.

### 2.3 Commit + announce + deploy

Per Charter HT5 (destructive announce) — the deploy force-pushes `publish` and tags the previous tip as `publish-prev` (POSTMORTEM follow-up #5 — cheap revert via `git push -f origin publish-prev:publish`):

```bash
cd /home/user/Desktop/static_store

# Announce in chat first (publish is force-push to gh-pages)
# Format: lane=publish + idem_key + paths added/removed/changed

# Stage submodule pointer (Case A) or plain-tree (Case B)
git add packages/hrbrlife/melusina_ccashconfig_app
git commit -m "catalog: add cca.sh Config v0.1.0 (admin-pearl landing, kill-list M1)"

# Deploy with auth gate set
MELUSINA_PUBLISH_AUTHORITATIVE=1 make deploy
```

The Makefile already tags `publish-prev` before force-pushing (Makefile lines 145–155). Revert recipe stays:

```bash
git push -f origin publish-prev:publish
```

### 2.4 Post-deploy verify

```bash
curl -sL https://bazaar.melusina-os.org/apps/index.json \
  | python3 -c "import json,sys; d=json.load(sys.stdin); \
                cfg=[a for a in d['apps'] if a['appId'].startswith('6gdgveud')]; \
                print('present' if cfg else 'MISSING'); \
                print(cfg[0].get('packageId','?') if cfg else '')"
```

Expected: `present`, packageId hash beginning `d0fd938f`. If not, the publish failed silently; revert via the publish-prev tag and investigate.

---

## 3. v0.2.0 path (kill-list M3)

Same procedure as §2 with `version: 0.2.0`. The expected `app_hash` will change — **the deployer agent (Worf) must reseat the on-chain ReleaseEntry to the new packageId before this static_store can publish**. If Worf hasn't reseated, preflight Gate 2 fails; do not override.

The `versionNumber` (the integer the Sandstorm Update mechanism uses to compare versions) increments by 1 vs v0.1.0. `metadata.json` carries both the human `version` string and the integer `versionNumber`.

---

## 4. Failure modes (and what to do)

| Failure | Cause | Action |
|---|---|---|
| `make build` doesn't pick up the new entry | metadata.json missing required fields, or appId typo | Verify `metadata.json.appId == 6gdgveudrer5a61hp8qkmxcn89wyce5uq1mg92ud40ugr2uj7mz0` and `metadata.json.versionNumber` is a positive integer |
| Preflight Gate 2 fails | local `.spk` SHA256 ≠ deployer manifest `app_hash` | Either (a) Worf reseats the on-chain entry to current bytes, or (b) re-pack the .spk deterministically to match expected. Do **not** override. |
| Preflight Gate 1 reports REMOVED apps unrelated to this entry | This static_store is a partial mirror | This is `POSTMORTEM.md` follow-up #1. Either set `MELUSINA_PUBLISH_SHRINK_OK=1` (if shrink is intentional) or stage the missing apps before deploying. **Do not silently override** — re-route the canonical-builder decision to Riker first. |
| `validate_release_attestation` fails in `build-store.sh` | `RELEASE.json` doesn't validate against on-chain `ReleaseEntry` | `melusina-pearl-tool` mis-attest, or the chain hasn't propagated. Wait one block; retry. If still failing, route to the admin-pearl agent (the Squads tx may need re-signing). |
| ccash claims `admin-gate` Grapple successfully but install user doesn't see the app in their bazaar | `cca.sh Config` not yet in the user's Sandstorm install (different from being in static_store) | The user uses the install's Sandstorm admin UI: **login as admin → Admin panel → App sources → Update / Refresh → install from market** (Charter HT12). This is unrelated to the static_store publish; it's a per-install action. |

---

## 5. What this procedure does **not** do

- Does **not** advance the kill-list M1 milestone — that's owned by the admin-pearl agent (task A1). M1 is "handshake alive end-to-end"; that test runs against the live Sandstorm install, not gh-pages.
- Does **not** add other catalog apps. `cca.sh Wholesale`, `cca.sh Domain Template`, and `TeleScreen` were the original POSTMORTEM follow-up #3 batch and are now all live; this procedure stays scoped to `cca.sh Config` re-publishes only.
- Does **not** change the Sandstorm bundle (`update/sandstorm-0.tar.xz`) — admin-pearl landing has zero coupling to the bundle.
- Does **not** mint or rotate the Solana ReleaseEntry — that's the deployer agent (Worf) and the admin-pearl agent's Squads multisig, not static_store.

---

*End of procedure. A1+A2 GREEN; v0.0.1 landed 2026-04-26. For v0.2.0+ re-publishes, re-verify (1)–(5) of §1 and run §2 in order.*
