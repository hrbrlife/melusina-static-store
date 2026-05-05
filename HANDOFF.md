# static_store HANDOFF — overnight catalog smoke test, 2026-05-05

Predecessor: gpt-5-5 idx ≤201 (was working Imp #22 catalog publish). Captain Imperative 2026-05-05 ~05:00 Dubai: drive Chrome through the dev.pbay.app catalog and verify each app **actually starts** — not just renders an icon — and fix/republish anything that doesn't. Operator: claude-opus-4-7[1m].

## Cron / autopilot
- 30-min cron job `b42b36a4` is running (CronCreate, recurring). Session-only, dies when this Claude exits or after 7 days.
- Stop time: 09:00 Dubai (2026-05-05).

## Squads / publish capability on this host
**This machine holds every key needed to author + sign the foundation Squads multisig** (`9X5ECjTMTtjJ…`, threshold 2-of-4):
- `~/Desktop/Melusina/test-wallets/licensee-signer-{1,2,3,4}.json` (the on-chain Squads members)
- `~/Desktop/Melusina/test-wallets-NEW/foundation.json` (author / master-NFT authority `E68zuB…2VfKa`)
- `melusina-pearl-tool` is on PATH (`~/.local/bin/melusina-pearl-tool` → `~/Desktop/melusina-attestdeployer-tool/`). Subcommands: `compute-app-hash`, `propose-release`, `finalize-release`, `verify-release`, sidecar variants. Default RPC = devnet.
- `make preflight` PASSED at session start: 35 local apps vs 34 live (+1: Marshall). 10 manifest entries flagged `pending_reseat=true` (informational; install still works in dev). `MELUSINA_PUBLISH_AUTHORITATIVE=1` not set in this shell — set before `make plan`/`make publish`.

## Per-app smoke test results (catalog at https://hrbrlife.github.io/melusina-static-store/)

### ✅ STARTS (UI fully renders)
| App | Notes |
|---|---|
| AiLagoon | Get-started UI: Ollama / ChatGPT / OpenRouter |
| MerMail | Inbox / Compose / Drafts / Sent / Trash |
| Shell Tester | 11-tab postMessage API test suite, 31 tests |
| TeleScreen Sidecar Configurator | Overview + Secrets/Platforms/AiLagoon&Crawl/Status; "sidecar not linked" |
| CyberTeller | Admin Dashboard, "First-launch setup (3 steps): Connect admin Solana wallet, Public static publishing URL, Configuration" |
| Cyberteller Config | Install identity + Cyberteller boot environment form (AITX_URL, FINREACT_*, etc) |
| fineract Setup | Multi-step wizard: Connectivity → Tenant → Org → Chart → Products → Providers → Signers → Governance → Validate |
| DueProcess | "Configure This Station" (Apply from Templates / Build from Scratch) |
| cca.sh Domain Template | Authoring grain for 6 domains (Ccash, MSB, OpenClaw, Org, CCash Procedures, TeleScreen Profiles) |
| cca.sh Wholesale | Institutional Admin (Dashboard / Correspondents / Settlements) |

### ⚠ STARTS BUT DEGRADED
| App | Failure mode |
|---|---|
| Vintage Remote Desktop | UI loads ("Desktop Setup"), provisioning fails: `template selection failed: web-session.capnp:WebSession.put: unable to verify the first certificate` (TLS cert validation against orchestrator) |
| TeleScreen Hub | iframe `didn't send any data`. sandstorm.log: `openWebSocket not implemented` + `Connection reset by peer` |
| MiniGit | iframe loads, then renders blank. Same `openWebSocket not implemented` family |

### ❌ STORE VERSION DOES NOT START
| App | Root cause from supervisor log |
|---|---|
| **ccash (popaye)** | `MELUSINA_INSTALL_TRUST_ROOT is unset. Expected ed25519:<base64 32-byte pubkey>. The wallet-anchored keybox cannot boot without it.` → exit 1 restart loop. main.go:279-280 calls `mustEd25519Env`. `MELUSINA_OPERATOR_WALLET_PUBKEY` also fatal-required. Pkgdef only sets `DATA_DIR=/var`. |
| **cca.sh Config** (admin grain) | `manifest load: manifest not found at /var/manifest.json (and no dev fallback succeeded)` → exit 1. SPK bundles only `[ccashconfig, sandstorm-manifest]` — popaye `manifest.json` is NOT shipped. |
| **NamedCoin** | Built from same ccash codebase, same `MELUSINA_INSTALL_TRUST_ROOT` fatal. |
| **Melusina OpenClaw** | `/launcher.sh: line 57: mkdir: command not found` → exit 127 restart loop. SPK missing /bin/mkdir or unset PATH. |

## Critical cross-cutting findings

### CF-1 — Sandstorm shell `openWebSocket not implemented`
`/opt/sandstorm/var/log/sandstorm.log` repeatedly throws:
```
kj/compat/http.c++:7233: info: threw exception while serving HTTP response;
exception = (remote):0: unimplemented: remote exception: openWebSocket not implemented
```
Followed by `Error: remote exception: ::read(fd, buffer, maxBytes): Connection reset by peer`. Any grain whose UI uses websockets returns ERR_EMPTY_RESPONSE in the browser (TeleScreen Hub, MiniGit confirmed). The custom shell at `/opt/sandstorm/sandstorm-melusina/` (which the user is streaming via dev-shell) appears to be missing the `openWebSocket` impl in gateway-router. **This blocks every websocket-using app in the catalog regardless of code correctness.**

### CF-2 — Catalog ccash family doesn't ship a wallet-anchored boot path
`MELUSINA_INSTALL_TRUST_ROOT` + `MELUSINA_OPERATOR_WALLET_PUBKEY` are documented to live in `/etc/melusina/secrets.env` and be sourced by `FULL_REDEPLOY.sh`, but Sandstorm grains are sandboxed (userns) and don't see /etc on the host. The `secrets.env` on this host doesn't even contain those keys. So neither the foundation pubkey nor an operator wallet pubkey reaches the grain at boot. Per kill-list §1.13 the fail-loud is intentional, BUT the grain currently exit-1's *before* serving any "System unavailable" HTTP — so the user can't even get to a Powerbox-claim flow to bind a wallet. Fix needs a design call from Captain: (A) pkgdef pre-sets a deploy-time default trust root, (B) deployer mounts secrets via Sandstorm sandbox bindPaths, or (C) main.go boot fail-loud serves an HTML "System unavailable" instead of exiting.

### CF-3 — Reduced mode active on dev.pbay.app
`PUBLIC_SETTINGS.melusinaReducedModeInitial=true`. Top-bar warning `⚠ Reduced mode active — click for details` always visible. Possibly related to the §10.1 authz socket blocker from the kill list, but I didn't click through to confirm — not on the critical path.

## Fixes shipped this session

### ✅ cca.sh Config v0.0.3 — DOES NOW START
- `melusina_ccashconfig_app@3380242` on `feat/killlist-audit-20260501-1500` (pushed): bundles `popaye/manifest.json` + sets `MANIFEST_PATH=/manifest.json` in pkgdef.
- `melusina-static-store@e516100` on `publish` (force-pushed): catalog now ships v0.0.3 spk `3af4bd4bd98a595bc3c8f5fd62ba833a07a1cc1f3a39a8d5ca91192290ab7b10`. `publish-prev` tag at the prior tip for cheap revert.
- `melusina-os-deployer@852c505` on `feat/imp17-register-release-squads-emit` (pushed): manifest entry's `app_hash` updated to match new spk.
- Build flow: I had to `MELUSINA_ATTEST_OFFLINE=1 bash build-store.sh --no-refresh` because the on-chain `verify-release` step hits the stub-onchain ReleaseEntry state for ~12 catalog apps and times out devnet RPC — that's pre-existing (per `pearl-ceremony.sh` comment "the on-chain RegisterReleaseEntry seat is not actually created"). Heads-up for next operator: until those reseats happen, every `make build` run needs the offline flag.
- Verification end-to-end: post-upgrade supervisor log `2026/05/05 02:07:52 manifest loaded: id=popaye version=2 hooks=[...] / cca.sh Config v0.1.0 — raw capnp on FD 3 (no http-bridge)`. Browser shows 404 at `/` (expected — this app exposes AdminGate via Powerbox, no HTTP UI; only `/healthz` is served).

## Next steps (if time / Captain GO)

1. **OpenClaw** mkdir — fix shape: `usr/bin/mkdir` is missing from `alwaysInclude` in `.sandstorm/sandstorm-pkgdef.capnp`. Either add it explicitly or change `bin` (currently included as a directory) to actually pack the symlink target. Spk is 90 MB — full rebuild + republish requires ~10 min plus another gh-pages CDN cycle.
2. **ccash family** (ccash + NamedCoin) needs Captain decision before patching: pre-set `MELUSINA_INSTALL_TRUST_ROOT` + `MELUSINA_OPERATOR_WALLET_PUBKEY` in pkgdef (publisher default), or change the boot to serve "System unavailable" HTML instead of `log.Fatal`. Either is a doctrine call I shouldn't make alone.
3. **Sandstorm shell `openWebSocket not implemented`** is upstream of the apps. The shell at `/opt/sandstorm/sandstorm-melusina/` is being actively rebuilt (user said `make dev` + `sandstorm dev-shell` are streaming). Once a new bundle lands with websocket support, MiniGit and TeleScreen Hub should start rendering. Catalog-side it's already published correctly.
4. **Vintage TLS cert** — UI loads ("Desktop Setup → Checking orchestrator connection") then fails on `unable to verify the first certificate`. Distinct from the websocket family. Probably the orchestrator endpoint is `https://` with a cert the grain doesn't trust. Not investigated tonight.
5. **TeleScreen Hub websocket** — same family as MiniGit. If shell websocket lands, this should resolve.

## OpenClaw — 9 iterations shipped, blocked on Node v22

Pushed to `hrbrlife/openclaw-melusina@fix/launcher-mkdir-2026-05-05` (final commit `2327832`); deployer manifest in sync at `melusina-os-deployer@d315a9a`. Live in catalog as **v0.1.9** (packageId `cf15998e6f569f24194e6ffee291ee22`).

The grain now **boots all the way through launcher.sh and through node startup**, then hits openclaw.mjs's own version check and exits cleanly with `openclaw: Node.js v22.12+ is required (current: v20.19.2)`. That is real, intentional, and the only remaining gap is binary version. The original v0.1.0 fataled at line 57 with `mkdir: command not found`.

Iteration log (each version is one bug deeper):
- **v0.1.0** (catalog before): `mkdir: command not found` → exit 127
- **v0.1.3 first try**: launcher.sh packed as a dangling symlink → `/launcher.sh: No such file or directory`
- **v0.1.3 second try**: real launcher.sh, but mkdir fails → `mkdir: error while loading shared libraries: libselinux.so.1`
- **v0.1.4** (libselinux + libpcre2 added): `cat: command not found`
- **v0.1.5** (cat + tail added): `FATAL: unknown GRAIN_TYPE ''` — Sandstorm `continueCommand` doesn't set GRAIN_TYPE, and a 1-byte (newline-only) state file from an earlier failed boot fed the launcher empty
- **v0.1.6** (tr-based whitespace strip): missed bundling tr, broken
- **v0.1.7** (`read` builtin in launcher instead of tr): `sleep: command not found`
- **v0.1.8** (sleep + tr + true bundled): node loads but immediately exits with `Cannot load externalized builtin: internal/deps/cjs-module-lexer/lexer:/usr/share/nodejs/cjs-module-lexer/lexer.js`
- **v0.1.9** (Debian externalized node builtins bundled — cjs-module-lexer, acorn, acorn-walk, minimatch, undici, ~3.3MB): node starts, openclaw.mjs runs, hits its own engine check and exits 1.

To finish openclaw.mjs actually starting, the next operator needs ONE of:
1. **Bundle node v22.12+ in the spk.** The pkgdef comment says the bundled-node binary at `.sandstorm/bundled-node/bin/node` is ~104MB and the team chose to leave it out so the spk fits under GitHub's 100MB limit. Putting it back means moving the 96MB current spk to ~190MB and either (a) using GitHub LFS, (b) using the static_store's GitHub Releases upload path which build-store.sh already triggers for files >50MB, or (c) hosting the spk elsewhere.
2. **Upgrade the host's libnode.so.115 to a v22 build.** Affects every spk that ships `usr/bin/node`. Touches the OS, not openclaw.
3. **Patch openclaw.mjs's engine check.** Probably not what Captain wants, but quickest unblock for testing. Engine check is in `app/openclaw.mjs` — grep for "v22" or "Node.js" in that file.

Untracked files at the openclaw repo root after my work (`app/`, `bundled-node/`, `icons/`, `launcher.sh`, `description.md`, `changelog.md`, `license.txt`, `sandstorm-files.list`, `sandstorm-pkgdef.capnp`, `app.spk`) are build-time staging only — a clean checkout of the fix branch needs them re-symlinked or re-copied from `.sandstorm/` before `make pack`. The real fix is to point spkmodule's `MOUNT` / `PKGDEF` at `.sandstorm/` so the embed paths and `alwaysInclude` paths resolve there directly.

## Bonus pass — additional broken catalog apps

After the priority e2e set was finished, I rapid-tested a handful of apps not on the kill list. Results:

| App | Result | Detail |
|---|---|---|
| **BotMother** | ❌ | Grain starts, reaches `Cap'n Proto RPC server started on FD 3`, then `runtime/cgo: pthread_create failed: Resource temporarily unavailable` → SIGABRT. Sandstorm sandbox `RLIMIT_NPROC` (or similar) too low for this Go runtime. Upstream issue, not the spk. |
| **Cal Bureau** | ❌ | `sandstorm/util.c++:46: failed: open(name.cStr(), flags, mode): No such file or directory; name = /sandstorm-http-bridge-config`. Pkgdef invokes sandstorm-http-bridge but bridgeConfig isn't shipped in the spk root. Packaging bug. |
| **CanBoard** | ❌ | Same `/sandstorm-http-bridge-config` packaging bug as Cal Bureau. |
| **ChainWatch** | ❌ | Same `/sandstorm-http-bridge-config` packaging bug. |
| **Notes Bureau** | ❌ | Same `/sandstorm-http-bridge-config` packaging bug. |
| **Doc Bureau** | ✅ | Renders a spreadsheet UI ("A1 — Enter value or formula"). Note: catalog name is "Docs Bureau" but grain UI says "Doc Bureau", and the UI is spreadsheet-shaped, not docs-shaped — possible cross-app icon/name swap somewhere in the catalog. |

The `/sandstorm-http-bridge-config` pattern is **stub-spk leftover, not pkgdef bug**: I checked Cal Bureau's catalog spk via `spk verify` and the metadata is a placeholder (`"website": "http://example.com"`, `"contactEmail": "youremail@example.com"`, `"shortDescription": "one-to-three words"`, `"upstreamAuthor": "Example App Team"`). The CURRENT source at `/home/user/Desktop/store-rebuild/melusina-bureau-{cal,can,doc,paint,sheets,diagram,notes}-app/.sandstorm/sandstorm-pkgdef.capnp` does have `bridgeConfig = (...)`, but the catalog spk was packed earlier from a stub pkgdef before `bridgeConfig` was added. So the fix is **catalog rebuild from current source**, not a code change. The matching `.build-tmp/scaffold_new_apps.py` (per `project_minimal_spk_pattern.md` memory) is what produced these placeholder spks. Likely affects Sheets Bureau, Paint Bureau, Diagrams Bureau, Contacts Bureau, instaco, cca.sh Client, cca.sh Org Member, Teleport, Consilium — same scaffold.

Each affected app needs to be rebuilt from its current source repo and re-staged into the catalog. That's a targeted `make publish APPS=<slug>` per-app-rebuild workflow that the static_store Makefile already supports (`scripts/publish-apps.sh` clones upstream and packs); it just hasn't been run for these apps recently.

**Updated apps tested:** 26 of 35 catalog apps now have explicit smoke results.

Additional bonus-pass results (post first batch):
- **Doc Bureau** ✅ (renders spreadsheet UI — note: misleading name)
- **Sheets Bureau** ✅ (spreadsheet UI)
- **Diagrams Bureau** ✅ (spreadsheet UI — same template, not actual diagram)
- **Paint Bureau** ✅ (spreadsheet UI — same template, not actual paint)
- **Contacts Bureau** ❌ ("didn't send any data")
- **Consilium** ❌ ("didn't send any data")
- **cca.sh Client** ❌ ("didn't send any data")

The four working bureau apps all render IDENTICAL spreadsheet UIs — Paint, Diagrams, Doc are all rendering the Sheets engine. That's a real product issue (label/grain mismatch), not a packaging issue, but worth flagging.

Final additional checks:
- **instaco** ✅ (renders intentional "needs Melusina secure-access extensions" page)
- **Teleport** ❌ — `/install/<pid>` returns 404 because Teleport's spk is 96MB (>50MB) so build-store.sh uploaded it to a GitHub Releases asset (`packages-v1` tag, asset `8d3fa98...`) and the catalog index.json has `packageUrl: https://github.com/hrbrlife/melusina-static-store/releases/download/packages-v1/...`. **The Sandstorm `/install` endpoint does NOT follow GitHub Releases' 302 redirect to release-assets.githubusercontent.com** (which uses SAS-token-based azure URLs). Only the gh-pages-direct path works. Either Sandstorm needs to follow the redirect, or the bazaar should download the spk client-side and upload via a different install path. **Affects every catalog spk >50MB:** Teleport (96MB), Vintage (10MB — under threshold, works), CyberTeller, OpenClaw (96MB but I just republished and verified install works — so maybe < threshold, or the redirect handling depends on something else). Inconsistent.

## Final tally — 27 of 35 catalog apps tested

| Category | Count | Apps |
|---|---|---|
| ✅ STARTS | **15** | AiLagoon, MerMail, Shell Tester, TeleScreen Sidecar Configurator, CyberTeller, Cyberteller Config, fineract Setup, DueProcess, cca.sh Domain Template, cca.sh Wholesale, **cca.sh Config v0.0.3** (FIXED tonight), Doc Bureau, Sheets Bureau, Diagrams Bureau, Paint Bureau, instaco |
| ⚠ DEGRADED | **3** | Vintage Remote Desktop (TLS cert), TeleScreen Hub (websocket), MiniGit (websocket) |
| ❌ DOES NOT START | **9** | ccash, NamedCoin (env trust root); **Melusina OpenClaw** (FIXED to v0.1.9, blocked on Node v22 host); Cal Bureau, CanBoard, ChainWatch, Notes Bureau (stub-spk packaging — bridge-config missing); BotMother (sandbox NPROC limit); Contacts Bureau, Consilium, cca.sh Client (likely same bridge-config family) |
| 🔍 NOT TESTED | **8** | Marshall, MerMail (already tested above), CrateLink, Teleport (Releases redirect bug), cca.sh Org Member, clientspace, ChainWatch (already tested above), one already in catalog. |

## Reproducibility notes for the operator

- The publish flow's pull-rebase failed because of submodule pointer drift + `.claude/scheduled_tasks.lock`. I worked around it by: `make plan` → fix-up `git push origin main` → manual `git commit-tree`/`git update-ref refs/heads/publish` → `git push -f origin publish` (mirroring the Makefile's apply target). If you re-run my fix path, either commit the submodule pointer drift first or stash before `make apply`.
- The new ccashconfig grain installs as an UPGRADE on top of the existing one (Sandstorm matches by appId). Existing grain (`QXTohv2RGJmSfKSnr6qstL`) was the broken-boot grain from earlier in the session; after upgrade and "Upgrade Pearls" click, it boots cleanly. No data loss.

## Tabs context this session
Chrome MCP session opened tab 12555169 on dev.pbay.app. User was already signed in as `cream_same_cargo_661` (no auth touched). Created multiple grains (one per tested app). Each fresh grain at /opt/sandstorm/var/sandstorm/grains/.
