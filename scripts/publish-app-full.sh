#!/usr/bin/env bash
#
# publish-app-full.sh — one-shot end-to-end publish for a single app source.
#
# Pipeline (rewritten 2026-05-24 to use the canonical static_store
# ceremony driver; supersedes the broken in-repo `make publish` Phase
# A/B flow that stalled cycle14 for 4.6h on cosigner-vote gap):
#
#   1. Version bump      (skipped with --bump none)
#   2. build + pack       (make build && make pack in the source repo —
#                          `make pack` verify-strict failures are now
#                          benign per the spkmodule fix; SPK is written
#                          before verify)
#   3. Pearl ceremony     ← THE CORE WORK
#                          stage-into-catalog.sh stages the fresh SPK
#                          into the catalog pkg dir + regenerates
#                          metadata.json from the new pkgId, then
#                          pearl-app-ceremony.sh drives the full 3-of-4
#                          Squads ceremony INLINE on Solana devnet
#                          (vaultTransactionCreate → proposalCreate →
#                          3× proposalApprove → vaultTransactionExecute
#                          → finalize-release → verify-release) using
#                          the licensee keys at
#                          /home/user/Desktop/Melusina/test-wallets/
#                          core-app-team/. The finalized RELEASE.json
#                          lands directly in the catalog pkg dir.
#   4. Sealed-v3 submit (FEDERATED-STORE-MVP §C3) — REPLACES the old
#                          source-repo publish-branch / gh-pages force-
#                          push. Wraps the canonical RELEASE.json in a
#                          signed artifact envelope and POSTs it (+ SPK)
#                          to a store sidecar's gated POST /publish (the
#                          C2.3 single writer), then verifies the store-
#                          signed provenance receipt against the on-chain
#                          store_authority. Set MELUSINA_STORE_URL (+ the
#                          MELUSINA_PUBLISHER_KEY / MELUSINA_STORE_PUBKEY /
#                          MELUSINA_STORE_LICENSE_MINT / MELUSINA_STORE_RPC_URL
#                          env) to enable. No force-push fallback exists.
#   5. Deployer approval manifest update — auto-merges the new app_hash
#                          into the deployer manifest so subsequent
#                          deploys don't need MELUSINA_PUBLISH_ALLOW_
#                          MANIFEST_DRIFT=1.
#   6. Static_store catalog sync — sync-catalog.sh rebuilds dist-publish/.
#
# After this script: nothing — when MELUSINA_STORE_URL is configured the
# verifying store sidecar (the single writer) has already assembled and is
# serving the catalog (Step 4). The legacy `make deploy` gh-pages force-push is
# SUPERSEDED by the sidecar and is not part of this flow.
#
# Designed to be safe to re-run. Each step is idempotent or skip-when-up-to-date.
# Uses per-step env-var flags so an operator can opt out of a step (e.g.
# SKIP_CEREMONY=1 to publish offline-stub RELEASE.json).
#
# Usage:
#   publish-app-full.sh <app-source-dir> [--bump patch|minor|major|none]
#                                        [--skip ceremony,manifest,sync]
#                                        [--dry-run]
#
# Exit codes: 0 success; 1 step failure; 2 bad inputs.
#
set -euo pipefail

# Reproducible pack (deterministic packageId): the patched `spk pack`
# (sandstorm/src/sandstorm/spk.c++) honors SOURCE_DATE_EPOCH and pins archive mtimes
# to it, so `make pack` of the same source+version yields the SAME packageId every
# run. Without it, wall-clock mtimes made packageId a moving target — the root cause
# of the freeze-verify break (Riker WHIP / CT-MSB 9085). Default here covers direct
# invocations; publish-install-serve.sh also exports it. Overridable. CT-SDL 2026-07-01.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"   # 2024-01-01T00:00:00Z, fixed

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATIC_STORE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

APP_DIR=""
BUMP="patch"
SKIP=""
DRY_RUN=false

# Pre-flight: probe tooling. spk is required by ceremony + stage steps;
# melusina-pearl-tool gates on-chain signing.
HAS_SPK=false
HAS_PEARL_TOOL=false
command -v spk >/dev/null 2>&1 && HAS_SPK=true
command -v melusina-pearl-tool >/dev/null 2>&1 && HAS_PEARL_TOOL=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bump)    BUMP="$2"; shift 2 ;;
    --skip)    SKIP="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help)
      sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
    *)
      [[ -z "$APP_DIR" ]] || { echo "unknown arg: $1" >&2; exit 2; }
      APP_DIR="$1"; shift ;;
  esac
done

[[ -n "$APP_DIR" ]] || { echo "FATAL: app dir required" >&2; exit 2; }
[[ -d "$APP_DIR" ]] || { echo "FATAL: not a directory: $APP_DIR" >&2; exit 2; }

skip_step() { [[ ",${SKIP}," == *",$1,"* ]]; }

ok()    { printf '\033[0;32m[OK]\033[0m   %s\n' "$*"; }
info()  { printf '\033[0;36m[INFO]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
fail()  { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; exit 1; }
step()  { printf '\033[1;36m[STEP %s]\033[0m %s\n' "$1" "$2"; }

run_or_dry() {
  if $DRY_RUN; then
    info "DRY RUN — would: $*"
  else
    "$@"
  fi
}

cd "$APP_DIR"
APP_SLUG="$(basename "$APP_DIR")"
info "App: $APP_SLUG ($APP_DIR)"
info "Static store: $STATIC_STORE_ROOT"
info "Bump: $BUMP   Skip: ${SKIP:-(none)}   Dry-run: $DRY_RUN"
echo

# ---- Step 1: bump version ---------------------------------------------------
step 1 "version bump"
if [[ "$BUMP" == "none" ]]; then
  info "  skipping version bump (--bump none)"
else
  if $DRY_RUN; then
    "$SCRIPT_DIR/version-bump.sh" "$APP_DIR" "$BUMP" --dry-run
  else
    "$SCRIPT_DIR/version-bump.sh" "$APP_DIR" "$BUMP"
  fi
fi
echo

# ---- Step 2: build + pack ---------------------------------------------------
step 2 "build + pack"
# Ensure spkmodule submodule is populated (apps store it as a submodule;
# `make pack` only resolves when spkmodule/mk/core.mk is present).
if [[ -f "$APP_DIR/.gitmodules" ]] \
   && grep -q '\[submodule "spkmodule"\]\|spkmodule\.path' "$APP_DIR/.gitmodules" 2>/dev/null \
   && [[ ! -f "$APP_DIR/spkmodule/mk/core.mk" ]]; then
  info "  spkmodule submodule not initialized — running git submodule update --init"
  run_or_dry git -C "$APP_DIR" submodule update --init --depth 1 spkmodule
fi
# Some apps keep sandstorm-pkgdef.capnp at .sandstorm/ instead of the repo
# root. spkmodule's pack target bind-mounts the repo root and expects the
# pkgdef at /opt/app/sandstorm-pkgdef.capnp; create a relative symlink so it
# resolves transparently. The symlink is reversible — leave it in place so
# subsequent invocations are idempotent.
if [[ ! -e "$APP_DIR/sandstorm-pkgdef.capnp" \
   && -f "$APP_DIR/.sandstorm/sandstorm-pkgdef.capnp" ]]; then
  info "  pkgdef lives at .sandstorm/ — adding root symlink so pack can find it"
  $DRY_RUN || ln -sf .sandstorm/sandstorm-pkgdef.capnp "$APP_DIR/sandstorm-pkgdef.capnp"
fi
if [[ ! -f "$APP_DIR/Makefile" ]]; then
  warn "  no Makefile in $APP_DIR — skipping build/pack (caller responsible)"
else
  has_target() {
    # Use --question (-q) to check target existence. Exit codes:
    #   0 = target up-to-date, 1 = needs rebuild, 2 = no rule for target.
    # Either 0 or 1 means the target is defined (even if from an included
    # spkmodule fragment).
    make -C "$APP_DIR" -q "$1" >/dev/null 2>&1
    rc=$?
    [[ $rc -eq 0 || $rc -eq 1 ]]
  }
  if has_target build; then
    run_or_dry make -C "$APP_DIR" build
  else
    info "  no 'build' target; skipping"
  fi
  if has_target pack; then
    # `make pack` may exit non-zero on spk-verify-strict failures (stale
    # metadata.json pkgId vs fresh SPK pkgId — common when republishing
    # a repo that's evolved past its last successful publish). The SPK
    # itself is written BEFORE verify runs, so this is benign: we
    # tolerate the non-zero exit and rely on the post-pack SPK presence
    # check below to confirm the actual artifact landed. The downstream
    # ceremony path re-derives metadata.json from the fresh SPK anyway.
    if $DRY_RUN; then
      info "DRY RUN — would: make -C $APP_DIR pack"
    else
      if ! make -C "$APP_DIR" pack; then
        warn "  make pack returned non-zero — likely verify-strict drift; checking SPK presence to confirm benign"
      fi
    fi
    # Confirm the SPK actually landed where downstream steps expect it.
    # spkmodule defaults to $APP_DIR/app.spk via SPK_OUT; some app
    # Makefiles override (e.g., openclaw-main writes melusina-openclaw.spk).
    if ! $DRY_RUN; then
      SPK_PATH="$APP_DIR/app.spk"
      if [[ ! -f "$SPK_PATH" ]]; then
        # Look for any .spk file produced in the last 60s as a fallback
        FOUND_SPK="$(find "$APP_DIR" -maxdepth 2 -name '*.spk' -mmin -1 -type f 2>/dev/null | head -1)"
        if [[ -n "$FOUND_SPK" && -f "$FOUND_SPK" ]]; then
          warn "  pack produced $FOUND_SPK (not $SPK_PATH) — symlinking for downstream"
          ln -sf "$(realpath "$FOUND_SPK")" "$SPK_PATH"
        else
          fail "  pack target ran but no app.spk produced at $SPK_PATH (and no recent *.spk found)"
        fi
      fi
    fi
  elif $DRY_RUN; then
    info "  no 'pack' target visible (likely spkmodule submodule pending init); would resolve after init"
  else
    fail "  no 'pack' target reachable from $APP_DIR/Makefile — cannot continue without an SPK"
  fi
fi
echo

# ---- Step 3: ceremony (Squads sign) -----------------------------------------
step 3 "Pearl ceremony"
# Regenerate offline RELEASE.json by default whenever the SPK was just packed,
# so downstream catalog consumers see a release manifest that matches the
# new app_hash. The release-json-stub is deterministic — re-running with
# the same SPK produces byte-identical output.
SPK_FOR_REL=""
if [[ -f "$APP_DIR/app.spk" ]]; then
  SPK_FOR_REL="$APP_DIR/app.spk"
else
  # find newest .spk in app dir as fallback (for apps with custom SPK_OUT)
  SPK_FOR_REL="$(find "$APP_DIR" -maxdepth 2 -name '*.spk' -mmin -10 -type f 2>/dev/null | head -1)"
fi

regen_stub_release() {
  if [[ -z "$SPK_FOR_REL" || ! -f "$SPK_FOR_REL" ]]; then
    warn "  no SPK found — cannot regenerate RELEASE.json"
    return
  fi
  if [[ ! -f "$APP_DIR/metadata.json" ]]; then
    warn "  no metadata.json at $APP_DIR — release-json-stub requires one"
    return
  fi
  # K02: store-side release-json-stub-fallback deleted — no forged-stub fallback.
  # Stubs are gated behind explicit MELUSINA_ATTEST_OFFLINE; build-store.sh rejects
  # any stub that reaches the catalog (fail-closed). Prefer the real Pearl ceremony.
  if [[ "${MELUSINA_ATTEST_OFFLINE:-0}" != "1" ]]; then
    warn "  refusing to forge an offline-stub RELEASE.json (K02/K03): run the real Pearl"
    warn "  ceremony (core-app-team keys), or set MELUSINA_ATTEST_OFFLINE=1 for test-only mode"
    return
  fi
  local stub_bin="$APP_DIR/spkmodule/bin/release-json-stub"
  if [[ ! -x "$stub_bin" ]]; then
    warn "  release-json-stub not found at $APP_DIR/spkmodule/bin/release-json-stub"
    return
  fi
  local VER
  VER="$(APP_DIR="$APP_DIR" python3 -c '
import json, os
print(json.load(open(os.path.join(os.environ["APP_DIR"], "metadata.json"))).get("marketingVersion", "0.0.0"))
')"
  run_or_dry "$stub_bin" \
    --spk "$SPK_FOR_REL" \
    --metadata "$APP_DIR/metadata.json" \
    --output "$APP_DIR/RELEASE.json" \
    --version "$VER"
}

if skip_step ceremony; then
  warn "  --skip ceremony — regenerating offline-stub RELEASE.json (so it matches the new SPK hash)"
  regen_stub_release
elif [[ ! -f "$APP_DIR/spkmodule/mk/pearl.mk" ]]; then
  if [[ "${MELUSINA_ATTEST_OFFLINE:-0}" != "1" ]]; then
    warn "  no spkmodule/mk/pearl.mk — refusing to forge a stub (K02/K03); set MELUSINA_ATTEST_OFFLINE=1 for test-only mode"
  elif [[ -f "$APP_DIR/app.spk" ]]; then
    warn "  MELUSINA_ATTEST_OFFLINE=1 — running release-json-stub (test-only)"
    # Read marketingVersion from metadata.json without shell-interpolating the
    # path (avoid quoting bugs / injection from APP_DIR).
    VER="$(APP_DIR="$APP_DIR" python3 -c '
import json, os
p = os.path.join(os.environ["APP_DIR"], "metadata.json")
try:
    print(json.load(open(p)).get("marketingVersion", "0.0.0"))
except FileNotFoundError:
    print("0.0.0")
')"
    run_or_dry "$APP_DIR/spkmodule/bin/release-json-stub" \
        --spk "$APP_DIR/app.spk" \
        --metadata "$APP_DIR/metadata.json" \
        --output "$APP_DIR/RELEASE.json" \
        --version "$VER"
  else
    warn "  no $APP_DIR/app.spk — pack must have been skipped"
  fi
elif ! $HAS_PEARL_TOOL; then
  warn "  melusina-pearl-tool NOT on PATH — on-chain Squads ceremony SKIPPED; publishing with offline-stub RELEASE.json. Install melusina-pearl-tool for on-chain attestation."
  SKIP="${SKIP:+$SKIP,}ceremony"
else
  # ──────────────────────────────────────────────────────────────────────
  # Canonical static_store ceremony (proven by cycle14 publish wave
  # 2026-05-24, supersedes the old `make propose-release` + `make
  # finalize-release` in-repo flow).
  #
  # Why this path:
  #   - In-repo `make propose-release` only submits the Squads proposal
  #     (1 of 4 sigs). Cosigner approval (3-of-4) had to happen
  #     out-of-band before `make finalize-release` could succeed — no
  #     in-repo tooling existed for it, so the chain stalled.
  #   - `pearl-app-ceremony.sh` drives the full 7-step ceremony INLINE
  #     (vaultTransactionCreate → proposalCreate → 3× proposalApprove →
  #     vaultTransactionExecute → finalize-release → verify-release)
  #     using the static_store-bundled @sqds/multisig + the licensee
  #     keys at /home/user/Desktop/Melusina/test-wallets/core-app-team/.
  #   - It writes the finalized RELEASE.json directly into the catalog
  #     pkg dir, so sync-catalog in Step 6 picks it up automatically.
  #
  # Pre-req: APP_CATALOG_PATH must resolve. We auto-derive it by
  # extracting appId from the freshly-packed SPK and finding the
  # catalog pkg dir whose metadata.json carries the same appId.
  # Override with explicit APP_CATALOG_PATH env var if auto-detection
  # picks the wrong dir.
  # ──────────────────────────────────────────────────────────────────────
  CAT_PATH="${APP_CATALOG_PATH:-}"
  if [[ -z "$CAT_PATH" ]]; then
    if [[ ! -f "$SPK_FOR_REL" ]]; then
      fail "  ceremony: no SPK found — run make pack first"
    fi
    if ! $HAS_SPK; then
      fail "  ceremony: spk CLI not found on PATH — required to extract appId from SPK. Install sandstorm bin/spk."
    fi
    APP_ID_FROM_SPK="$(spk verify "$SPK_FOR_REL" 2>/dev/null | grep -oE '"appId": "[^"]*"' | head -1 | cut -d'"' -f4)"
    if [[ -z "$APP_ID_FROM_SPK" ]]; then
      fail "  ceremony: could not extract appId from $SPK_FOR_REL"
    fi
    # Find catalog pkg dir whose metadata.json holds this appId.
    # NB: `grep -l` exits 1 on non-matching files, which under `set -o
    # pipefail` makes a `find … | xargs grep -l | head -1` pipeline return
    # xargs's aggregate exit 123 and abort the whole driver (latent bug
    # hit 2026-06-02). Use `grep -rl` over the metadata.json set directly
    # and guard the exit code so a no-match is handled by the check below,
    # not by `set -e`.
    #
    # Prefer the canonical packages/<dev>/<app>/<app>/ dir that build-store.sh
    # actually scans over flat legacy mirror dirs packages/<pkgId>/. Multiple
    # dirs can share an appId; staging into a flat dir that build-store
    # ignores silently drops the publish from the index (hit 2026-06-02 —
    # wrong dir, index never advanced). Rank deeper (developer-nested) first.
    CAT_MATCHES="$(grep -rl --include=metadata.json \
                     "\"appId\": *\"$APP_ID_FROM_SPK\"" \
                     "$STATIC_STORE_ROOT/packages" 2>/dev/null || true)"
    CAT_PATH=""
    if [[ -n "$CAT_MATCHES" ]]; then
      CAT_PATH="$(printf '%s\n' "$CAT_MATCHES" \
        | awk -F/ '{ print NF"\t"$0 }' \
        | sort -rn | head -1 | cut -f2-)"
    fi
    CAT_PATH="${CAT_PATH%/metadata.json}"
    if [[ -z "$CAT_PATH" || ! -d "$CAT_PATH" ]]; then
      fail "  ceremony: could not locate catalog pkg dir for appId=$APP_ID_FROM_SPK — set APP_CATALOG_PATH= explicitly"
    fi
    info "  catalog pkg dir auto-detected: $CAT_PATH"
  fi

  # Stage fresh SPK into catalog (extracts new pkgId, updates catalog
  # metadata.json, regenerates RELEASE.json offline-stub so it matches).
  info "  staging SPK into catalog"
  if ! run_or_dry "$STATIC_STORE_ROOT/scripts/stage-into-catalog.sh" "$SPK_FOR_REL" "$CAT_PATH"; then
    fail "  stage-into-catalog failed for $SPK_FOR_REL → $CAT_PATH"
  fi

  # Drive the 3-of-4 Squads ceremony inline + verify-release.
  CEREMONY_VER="$(APP_DIR="$APP_DIR" python3 -c '
import json, os
print(json.load(open(os.path.join(os.environ["APP_DIR"], "metadata.json"))).get("marketingVersion", "0.0.0"))
' 2>/dev/null || echo "0.0.0")"
  info "  invoking pearl-app-ceremony.sh (3-of-4 Squads sign on Solana devnet)"
  if ! APP_CATALOG_PATH="$CAT_PATH" APP_SLUG="$APP_SLUG" MELUSINA_VERSION="$CEREMONY_VER" \
       run_or_dry "$STATIC_STORE_ROOT/scripts/pearl-app-ceremony.sh"; then
    fail "  pearl-app-ceremony.sh failed — see /tmp/pearl-ceremony-$APP_SLUG/ for state"
  fi
  # The ceremony writes the appHash into its RELEASE.json (and the catalog
  # RELEASE.json), NOT into result.json (which carries only Squads tx ids).
  # Prefer the ceremony RELEASE.json, then the catalog RELEASE.json, then a
  # legacy result.json.appHash. Getting this non-empty is load-bearing: it
  # selects the Step 4 branch that SKIPS the source-repo `make publish`
  # (which re-packs and FATALs on the signature-derived pkgId drift — the
  # "Phase B finalize-release pkgId-drift" failure mode).
  PUBLISHED_APP_HASH="$(jq -r '.appHash // empty' "/tmp/pearl-ceremony-$APP_SLUG/RELEASE.json" 2>/dev/null || true)"
  if [[ -z "$PUBLISHED_APP_HASH" && -f "$CAT_PATH/RELEASE.json" ]]; then
    PUBLISHED_APP_HASH="$(jq -r '.appHash // empty' "$CAT_PATH/RELEASE.json" 2>/dev/null || true)"
  fi
  if [[ -z "$PUBLISHED_APP_HASH" ]]; then
    PUBLISHED_APP_HASH="$(jq -r '.appHash // empty' "/tmp/pearl-ceremony-$APP_SLUG/result.json" 2>/dev/null || true)"
  fi
  if [[ -n "$PUBLISHED_APP_HASH" ]]; then
    info "  ceremony complete — appHash=$PUBLISHED_APP_HASH"
  else
    warn "  ceremony complete but appHash not found in RELEASE.json/result.json — Step 4 may attempt make publish (re-pack)"
  fi
fi
echo

# ---- Step 4: sealed-v3 submit to the store sidecar (C3) ----------------------
# FEDERATED-STORE-MVP §C3: this step REPLACES the old gh-pages/source-repo
# force-push. We no longer push a `publish` branch anywhere; instead we wrap the
# canonical RELEASE.json in a signed artifact envelope and POST it (+ the SPK) to
# a store sidecar's gated POST /publish (the C2.3 single writer). The sidecar
# verifies on-chain and returns a store-signed provenance receipt, which the
# submit client verifies against the on-chain store_authority before succeeding.
# The force-push path is DELETED — there is no `make -C "$APP_DIR" publish`
# fallback here. (gh-pages itself is force-pushed only by the legacy
# static_store `make apply`, which the verifying sidecar supersedes; this driver
# never invokes it.)
step 4 "sealed-v3 submit to store sidecar"
SUBMIT_BIN="$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar/bin/submit"

# Locate the RELEASE.json produced by Step 3 and the release-bound runtime
# contract (ceremony catalog dir first, then the app dir). The Pearl finalizer
# intentionally knows only the on-chain manifest fields, so it strips the two
# runtime-contract fields. We restore them after finalization and before the
# submit client signs the exact publisher envelope.
#
# The submit client asserts apphash(SPK,metadata.json)==RELEASE.appHash locally —
# the on-chain appHash is the tree-hash over {app.spk, metadata.json}, so the
# metadata.json is REQUIRED alongside the SPK + RELEASE.json. The runtime
# contract stays outside that appHash pair and separately names the exact SPK.
SUBMIT_RELEASE=""
SUBMIT_METADATA=""
SUBMIT_RUNTIME_CONTRACT=""
if [[ -n "${CAT_PATH:-}" && -f "$CAT_PATH/RELEASE.json" ]]; then
  SUBMIT_RELEASE="$CAT_PATH/RELEASE.json"
elif [[ -f "$APP_DIR/RELEASE.json" ]]; then
  SUBMIT_RELEASE="$APP_DIR/RELEASE.json"
fi
if [[ -n "${CAT_PATH:-}" && -f "$CAT_PATH/metadata.json" ]]; then
  SUBMIT_METADATA="$CAT_PATH/metadata.json"
elif [[ -f "$APP_DIR/metadata.json" ]]; then
  SUBMIT_METADATA="$APP_DIR/metadata.json"
fi
if [[ -n "${CAT_PATH:-}" && -f "$CAT_PATH/RUNTIME-CONTRACT.json" ]]; then
  SUBMIT_RUNTIME_CONTRACT="$CAT_PATH/RUNTIME-CONTRACT.json"
elif [[ -f "$APP_DIR/RUNTIME-CONTRACT.json" ]]; then
  SUBMIT_RUNTIME_CONTRACT="$APP_DIR/RUNTIME-CONTRACT.json"
fi

if skip_step push || skip_step submit; then
  warn "  --skip submit — not POSTing to a store sidecar (local-only)"
elif [[ -z "${MELUSINA_STORE_URL:-}" ]]; then
  warn "  MELUSINA_STORE_URL not set — skipping sealed submit."
  warn "  To publish to the verifying store sidecar, set: MELUSINA_STORE_URL,"
  warn "  MELUSINA_PUBLISHER_KEY, MELUSINA_STORE_PUBKEY, MELUSINA_STORE_LICENSE_MINT,"
  warn "  MELUSINA_STORE_RPC_URL (see Makefile target 'publish-sealed')."
elif [[ -z "$SUBMIT_RELEASE" || ! -f "$SUBMIT_RELEASE" ]]; then
  fail "  submit: no RELEASE.json found (looked in \$CAT_PATH and $APP_DIR) — run the ceremony (Step 3) first"
elif [[ -z "$SUBMIT_METADATA" || ! -f "$SUBMIT_METADATA" ]]; then
  fail "  submit: no metadata.json found (looked in \$CAT_PATH and $APP_DIR) — it is bound into the on-chain appHash"
elif [[ -z "$SUBMIT_RUNTIME_CONTRACT" || ! -f "$SUBMIT_RUNTIME_CONTRACT" ]]; then
  fail "  submit: no RUNTIME-CONTRACT.json found (looked in \$CAT_PATH and $APP_DIR) — every new Bazaar publish requires one"
elif [[ -z "$SPK_FOR_REL" || ! -f "$SPK_FOR_REL" ]]; then
  fail "  submit: no SPK found — run make pack (Step 2) first"
else
  # Build the submit client on demand if it is not already compiled.
  if [[ ! -x "$SUBMIT_BIN" ]]; then
    info "  building submit client"
    run_or_dry make -C "$STATIC_STORE_ROOT" submit-build || fail "  submit-build failed"
  fi
  : "${MELUSINA_PUBLISHER_KEY:?MELUSINA_PUBLISHER_KEY required for sealed submit (path or env:NAME)}"
  : "${MELUSINA_STORE_PUBKEY:?MELUSINA_STORE_PUBKEY required (sidecar operator identity.Public JSON)}"
  : "${MELUSINA_STORE_LICENSE_MINT:?MELUSINA_STORE_LICENSE_MINT required (store operator license_nft_mint, base58)}"
  : "${MELUSINA_STORE_RPC_URL:?MELUSINA_STORE_RPC_URL required (Solana JSON-RPC for receipt verification)}"

  # Bind the exact contract after Pearl finalization. This mutation is atomic
  # and happens before the submit client signs the publisher envelope. The
  # author/Squads releaseHash remains sha256(appHash + version + nonce); the
  # envelope body hash binds this augmented RELEASE.json byte-for-byte.
  if $DRY_RUN; then
    info "  DRY RUN — would bind $SUBMIT_RUNTIME_CONTRACT into $SUBMIT_RELEASE"
  else
    python3 - "$SUBMIT_RELEASE" "$SUBMIT_RUNTIME_CONTRACT" <<'PY'
import hashlib, json, os, sys, tempfile

release_path, contract_path = sys.argv[1:3]
with open(contract_path, "rb") as fh:
    contract_hash = hashlib.sha256(fh.read()).hexdigest()
with open(release_path, "r", encoding="utf-8") as fh:
    release = json.load(fh)
release["runtimeContractSchema"] = "melusina-app-runtime-contract-v1"
release["runtimeContractSha256"] = contract_hash
directory = os.path.dirname(os.path.abspath(release_path))
fd, temporary = tempfile.mkstemp(prefix=".RELEASE.json.", dir=directory, text=True)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(release, fh, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(temporary, release_path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
    python3 "$STATIC_STORE_ROOT/scripts/validate-runtime-contract.py" \
      --contract "$SUBMIT_RUNTIME_CONTRACT" \
      --spk "$SPK_FOR_REL" \
      --metadata "$SUBMIT_METADATA" \
      --release "$SUBMIT_RELEASE" \
      || fail "  runtime contract does not match the finalized release artifacts"
  fi

  info "  POST $MELUSINA_STORE_URL/publish (single writer; NO force-push)"
  SUBMIT_ARGS=(
    --store "$MELUSINA_STORE_URL"
    --spk "$SPK_FOR_REL"
    --metadata "$SUBMIT_METADATA"
    --release "$SUBMIT_RELEASE"
    --runtime-contract "$SUBMIT_RUNTIME_CONTRACT"
    --publisher-key "$MELUSINA_PUBLISHER_KEY"
    --store-pubkey "$MELUSINA_STORE_PUBKEY"
    --license-mint "$MELUSINA_STORE_LICENSE_MINT"
    --rpc-url "$MELUSINA_STORE_RPC_URL"
  )
  [[ -n "${MELUSINA_STORE_DOMAIN:-}" ]]   && SUBMIT_ARGS+=(--domain "$MELUSINA_STORE_DOMAIN")
  [[ -n "${MELUSINA_VERIFIED_SLOT:-}" ]]  && SUBMIT_ARGS+=(--verified-slot "$MELUSINA_VERIFIED_SLOT")
  run_or_dry "$SUBMIT_BIN" "${SUBMIT_ARGS[@]}" || fail "  sealed submit to $MELUSINA_STORE_URL rejected the publish"
fi
echo

# ---- Step 5: update deployer approval manifest ------------------------------
step 5 "deployer approval manifest"
DEPLOYER_MANIFEST="${MELUSINA_DEPLOYER_MANIFEST:-/home/user/Desktop/Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json}"
if skip_step manifest; then
  warn "  --skip manifest"
elif [[ ! -f "$DEPLOYER_MANIFEST" ]]; then
  warn "  manifest not found at $DEPLOYER_MANIFEST"
elif [[ -n "${PUBLISHED_APP_HASH:-}" ]]; then
  # Step 3 used the canonical ceremony — we have the new appHash + the
  # catalog metadata.json already updated. Build the manifest entry
  # directly from those, no need for an in-repo make target.
  # This is what drops the need for MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1
  # on follow-up deploys.
  if $DRY_RUN; then
    info "  DRY RUN — would merge entry { app_hash=$PUBLISHED_APP_HASH ... } into $DEPLOYER_MANIFEST"
  else
    ENTRY="$(CAT_PATH="$CAT_PATH" PUBLISHED_APP_HASH="$PUBLISHED_APP_HASH" APP_NAME_OVERRIDE="${APP_NAME_OVERRIDE:-}" python3 -c '
import json, os
cat = os.environ["CAT_PATH"]
with open(os.path.join(cat, "metadata.json")) as f:
    md = json.load(f)
entry = {
    "app_name":  os.environ.get("APP_NAME_OVERRIDE") or md.get("name") or md.get("title", "?"),
    "app_id":    md["appId"],
    "app_hash":  os.environ["PUBLISHED_APP_HASH"],
    "version":   md.get("marketingVersion") or md.get("version", "0.0.0"),
    "author":    "hrbrlife",
}
print(json.dumps(entry, indent=2))
')"
    if [[ -n "$ENTRY" ]]; then
      printf '%s\n' "$ENTRY" \
        | "$STATIC_STORE_ROOT/scripts/manifest-merge.sh" \
            --manifest "$DEPLOYER_MANIFEST" --stdin \
        || warn "  manifest-merge.sh exited non-zero — deployer manifest may still drift"
      info "  deployer manifest updated with appHash=$PUBLISHED_APP_HASH (no MANIFEST_DRIFT flag needed on next deploy)"
    fi
  fi
elif ! make -C "$APP_DIR" -q approval-manifest-entry >/dev/null 2>&1 \
     && [[ "$(make -C "$APP_DIR" -q approval-manifest-entry >/dev/null 2>&1; echo $?)" == "2" ]]; then
  warn "  no approval-manifest-entry target — manifest unchanged"
else
  if $DRY_RUN; then
    info "  DRY RUN — would emit entry and merge into $DEPLOYER_MANIFEST"
  else
    ENTRY="$(make -C "$APP_DIR" approval-manifest-entry 2>/dev/null | sed -n '/^{/,/^}/p')"
    if [[ -z "$ENTRY" ]]; then
      warn "  approval-manifest-entry produced no output"
    else
      printf '%s\n' "$ENTRY" \
        | "$STATIC_STORE_ROOT/scripts/manifest-merge.sh" \
            --manifest "$DEPLOYER_MANIFEST" --stdin \
        || warn "  manifest-merge.sh exited non-zero"
    fi
  fi
fi
echo

# ---- Step 6: catalog sync ---------------------------------------------------
step 6 "static_store catalog sync"
if skip_step sync; then
  warn "  --skip sync — catalog NOT rebuilt"
else
  run_or_dry "$SCRIPT_DIR/sync-catalog.sh" --app "$APP_SLUG" \
    || fail "catalog sync failed"
fi
echo

ok "publish-app-full done for $APP_SLUG"
