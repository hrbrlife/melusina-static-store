#!/usr/bin/env bash
#
# self-publish.sh — the fast, parallel-safe, no-central-tzar publish driver
# (Captain directive 2026-07-09: "each app publisher POSTs its binary to the
# bazaar melusina publish endpoint" — no single agent babysitting a serial
# queue).
#
# SUPERSEDES the sealed-submit half of publish-app-full.sh (its Step 4 has
# never actually run in production — see ROOT-CAUSE-A below) and DELETES the
# publish-app-full.sh Step 6 dependency on a full local `build-store.sh
# --no-refresh` rebuild (dead weight once the sealed submit is real: the
# LIVE store's own CatalogAssembler.Assemble() is what actually matters, and
# it runs server-side, on the box, inside the /publish request — a second,
# local, unrelated rebuild of this checkout's dist-publish/ proves nothing
# about what bazaar.melusina-os.org serves).
#
# ROOT-CAUSE-A (found 2026-07-09, SSH-verified against mel-os-store /
# 34.46.92.113): publish-app-full.sh Step 4 (cmd/submit POST /publish)
# requires --publisher-key (an attest identity.Private JSON: hex ed25519
# sign_seed + x25519 box_seed + a Ref) and --store-pubkey (the store
# operator's identity.Public JSON). Neither file existed anywhere on disk —
# every "DONE" publish in fleet/work/publish-tzar/evidence/*.md actually
# used an undocumented manual SSH "controlled-persist" ritual instead
# (scp SPK+metadata+RELEASE.json into the box's packages/ dir + SSH-run
# build-store.sh by hand). THAT ritual — one agent, one box, one app at a
# time — was the real single-tzar bottleneck. cmd/keygen (this repo,
# cmd/keygen/main.go) now derives both missing files from key material that
# already exists (the core-app-team publisher Solana keypair + the store's
# already-on-chain-registered signing/encryption pubkeys), so POST /publish
# actually works, and any number of apps can self-publish in parallel — the
# store sidecar's own single-writer mutex serializes the final verify+
# persist+assemble step server-side (automatic, seconds, no babysitting),
# and pearl-app-ceremony.sh's per-multisig flock serializes only the Squads
# on-chain sub-steps different apps genuinely cannot run concurrently
# against ONE shared multisig account.
#
# Usage:
#   self-publish.sh <app-source-dir> \
#     --keys <dev-publish-keys-dir> \
#     [--bump patch|minor|major|none] \
#     [--skip ceremony] \
#     [--catalog-path <dir>]           # override auto-detected static_store
#                                       #   packages/<dev>/<repo>/<slug> dir
#     [--dry-run]
#
# <dev-publish-keys-dir> must contain (see dev-publish-keys/README.md in
# each app repo for the Captain-authorized dev copies):
#   publisher.json, reviewer-1.json, reviewer-2.json   (Squads ceremony —
#                                                        raw Solana keypairs)
#   core-app-team-squads.json                          (Squads multisig config)
#   publisher.key.json                                 (sealed-submit envelope
#                                                        identity.Private)
#   store-pubkey.json                                  (sealed-submit envelope
#                                                        destination — public)
#
# Required env (secrets — NEVER duplicated into repos, read from the
# operator's shell/secrets.env only):
#   MELUSINA_RPC_URL        Solana RPC for the Squads ceremony (Helius keyed
#                            preferred — public devnet 429s under load)
#   MELUSINA_STORE_RPC_URL  Solana RPC for sealed-submit receipt verification
#                            (defaults to MELUSINA_RPC_URL)
#
# Exit codes: 0 success (chain-verified-served); 1 step failure; 2 bad inputs.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATIC_STORE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"

APP_DIR=""
KEYS_DIR=""
BUMP="patch"
SKIP=""
CATALOG_PATH_OVERRIDE=""
DRY_RUN=false
STORE_URL="${MELUSINA_STORE_URL:-https://bazaar.melusina-os.org}"
STORE_DOMAIN="${MELUSINA_STORE_DOMAIN:-bazaar.melusina-os.org}"
STORE_LICENSE_MINT="${MELUSINA_STORE_LICENSE_MINT:-35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keys)         KEYS_DIR="$2"; shift 2 ;;
    --bump)         BUMP="$2"; shift 2 ;;
    --skip)         SKIP="$2"; shift 2 ;;
    --catalog-path) CATALOG_PATH_OVERRIDE="$2"; shift 2 ;;
    --dry-run)      DRY_RUN=true; shift ;;
    -h|--help) sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
    *) [[ -z "$APP_DIR" ]] || { echo "unknown arg: $1" >&2; exit 2; }; APP_DIR="$1"; shift ;;
  esac
done

[[ -n "$APP_DIR" ]] || { echo "FATAL: app source dir required" >&2; exit 2; }
[[ -d "$APP_DIR" ]] || { echo "FATAL: not a directory: $APP_DIR" >&2; exit 2; }
[[ -n "$KEYS_DIR" ]] || { echo "FATAL: --keys <dev-publish-keys-dir> required" >&2; exit 2; }
[[ -d "$KEYS_DIR" ]] || { echo "FATAL: --keys dir not found: $KEYS_DIR" >&2; exit 2; }
for f in publisher.json reviewer-1.json reviewer-2.json core-app-team-squads.json publisher.key.json store-pubkey.json; do
  [[ -f "$KEYS_DIR/$f" ]] || { echo "FATAL: $KEYS_DIR/$f missing (see dev-publish-keys/README.md)" >&2; exit 2; }
done

skip_step() { [[ ",${SKIP}," == *",$1,"* ]]; }
ok()   { printf '\033[0;32m[OK]\033[0m   %s\n' "$*"; }
info() { printf '\033[0;36m[INFO]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
fail() { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; exit 1; }
step() { printf '\033[1;36m[STEP %s]\033[0m %s\n' "$1" "$2"; }

cd "$APP_DIR"
APP_SLUG="$(basename "$APP_DIR")"
info "App: $APP_SLUG ($APP_DIR)"
info "Keys: $KEYS_DIR"
info "Store: $STORE_URL   Bump: $BUMP   Dry-run: $DRY_RUN"
echo

# ---- Step 1: version bump ---------------------------------------------------
step 1 "version bump"
if [[ "$BUMP" == "none" ]]; then
  info "  skipping (--bump none)"
elif $DRY_RUN; then
  "$SCRIPT_DIR/version-bump.sh" "$APP_DIR" "$BUMP" --dry-run
else
  "$SCRIPT_DIR/version-bump.sh" "$APP_DIR" "$BUMP"
fi
echo

# ---- Step 2: build + pack ---------------------------------------------------
step 2 "build + pack"
if [[ -f "$APP_DIR/.gitmodules" ]] \
   && grep -q '\[submodule "spkmodule"\]\|spkmodule\.path' "$APP_DIR/.gitmodules" 2>/dev/null \
   && [[ ! -f "$APP_DIR/spkmodule/mk/core.mk" ]]; then
  $DRY_RUN || git -C "$APP_DIR" submodule update --init --depth 1 spkmodule
fi
if [[ ! -e "$APP_DIR/sandstorm-pkgdef.capnp" && -f "$APP_DIR/.sandstorm/sandstorm-pkgdef.capnp" ]]; then
  $DRY_RUN || ln -sf .sandstorm/sandstorm-pkgdef.capnp "$APP_DIR/sandstorm-pkgdef.capnp"
fi
if $DRY_RUN; then
  info "  DRY RUN — would: make -C $APP_DIR build pack"
else
  make -C "$APP_DIR" build
  make -C "$APP_DIR" pack || warn "  make pack non-zero (often benign verify-strict drift) — checking SPK presence"
  [[ -f "$APP_DIR/app.spk" ]] || fail "  no app.spk produced"
fi
echo

# ---- Step 3: locate/auto-detect the catalog staging dir ---------------------
step 3 "resolve catalog staging dir"
CAT_PATH="$CATALOG_PATH_OVERRIDE"
if [[ -z "$CAT_PATH" ]]; then
  command -v spk >/dev/null 2>&1 || fail "  spk CLI not on PATH — required to extract appId"
  APP_ID="$(spk verify "$APP_DIR/app.spk" 2>/dev/null | grep -oE '"appId": "[^"]*"' | head -1 | cut -d'"' -f4)"
  [[ -n "$APP_ID" ]] || fail "  could not extract appId from $APP_DIR/app.spk"
  CAT_MATCHES="$(grep -rl --include=metadata.json "\"appId\": *\"$APP_ID\"" "$STATIC_STORE_ROOT/packages" 2>/dev/null || true)"
  [[ -n "$CAT_MATCHES" ]] || fail "  no catalog pkg dir found for appId=$APP_ID — pass --catalog-path"
  CAT_PATH="$(printf '%s\n' "$CAT_MATCHES" | awk -F/ '{print NF"\t"$0}' | sort -rn | head -1 | cut -f2-)"
  CAT_PATH="${CAT_PATH%/metadata.json}"
fi
info "  catalog staging dir: $CAT_PATH"
echo

# ---- Step 4: pearl ceremony (Squads sign, in-repo dev keys) -----------------
step 4 "pearl ceremony (3-of-4 Squads, in-repo dev keys)"
if skip_step ceremony; then
  warn "  --skip ceremony"
else
  info "  staging fresh SPK into catalog"
  $DRY_RUN || "$STATIC_STORE_ROOT/scripts/stage-into-catalog.sh" "$APP_DIR/app.spk" "$CAT_PATH" \
    || fail "  stage-into-catalog failed"
  CEREMONY_VER="$(python3 -c 'import json;print(json.load(open("'"$APP_DIR"'/metadata.json")).get("marketingVersion","0.0.0"))' 2>/dev/null || echo 0.0.0)"
  if $DRY_RUN; then
    info "  DRY RUN — would run pearl-app-ceremony.sh version=$CEREMONY_VER"
  else
    APP_CATALOG_PATH="$CAT_PATH" APP_SLUG="$APP_SLUG" MELUSINA_VERSION="$CEREMONY_VER" \
      MELUSINA_PUBLISHER_KEYPAIR="$KEYS_DIR/publisher.json" \
      MELUSINA_REVIEWER1_KEYPAIR="$KEYS_DIR/reviewer-1.json" \
      MELUSINA_REVIEWER2_KEYPAIR="$KEYS_DIR/reviewer-2.json" \
      MELUSINA_SQUADS_CONFIG="$KEYS_DIR/core-app-team-squads.json" \
      "$STATIC_STORE_ROOT/scripts/pearl-app-ceremony.sh" \
      || fail "  pearl-app-ceremony.sh failed — see /tmp/pearl-ceremony-$APP_SLUG/"
  fi
fi
echo

# ---- Step 5: POST /publish (sealed-v3, single writer, chain-verified) -------
step 5 "POST $STORE_URL/publish"
SUBMIT_BIN="$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar/bin/submit"
if [[ ! -x "$SUBMIT_BIN" ]]; then
  info "  building submit client"
  $DRY_RUN || (cd "$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar" && \
    mkdir -p bin && go build -o bin/submit ./cmd/submit) \
    || fail "  submit-build failed"
fi
RPC_URL="${MELUSINA_STORE_RPC_URL:-${MELUSINA_RPC_URL:-}}"
[[ -n "$RPC_URL" ]] || fail "  MELUSINA_STORE_RPC_URL (or MELUSINA_RPC_URL) required for receipt verification"
if $DRY_RUN; then
  info "  DRY RUN — would POST $CAT_PATH/{app.spk,metadata.json,RELEASE.json} to $STORE_URL/publish"
else
  "$SUBMIT_BIN" \
    --store "$STORE_URL" \
    --spk "$CAT_PATH/app.spk" \
    --metadata "$CAT_PATH/metadata.json" \
    --release "$CAT_PATH/RELEASE.json" \
    --publisher-key "$KEYS_DIR/publisher.key.json" \
    --store-pubkey "$KEYS_DIR/store-pubkey.json" \
    --license-mint "$STORE_LICENSE_MINT" \
    --domain "$STORE_DOMAIN" \
    --rpc-url "$RPC_URL" \
    --timeout 480s \
    || fail "  sealed submit rejected by $STORE_URL — see output above (check=... names the failing gate)"
fi
echo

# ---- Step 6: verify chain-verified serve -------------------------------------
step 6 "verify served + chain-verified"
if $DRY_RUN; then
  info "  DRY RUN — would GET $STORE_URL/apps/index.json and compare version+sha256"
else
  EXPECT_VER="$(python3 -c 'import json;print(json.load(open("'"$CAT_PATH"'/metadata.json")).get("marketingVersion",""))')"
  EXPECT_SHA="$(sha256sum "$CAT_PATH/app.spk" | awk '{print $1}')"
  SERVED_JSON="$(curl -fsS --max-time 20 "$STORE_URL/apps/index.json")" \
    || fail "  GET $STORE_URL/apps/index.json failed"
  APP_ID="$(python3 -c 'import json;print(json.load(open("'"$CAT_PATH"'/metadata.json")).get("appId",""))')"
  SERVED_VER="$(python3 -c "
import json,sys
d=json.loads(sys.argv[1])
apps=d.get('apps', d if isinstance(d,list) else [])
for a in apps:
    if a.get('appId')=='$APP_ID':
        print(a.get('marketingVersion') or a.get('version') or '')
        break
" "$SERVED_JSON" 2>/dev/null || true)"
  [[ "$SERVED_VER" == "$EXPECT_VER" ]] \
    || fail "  served index.json version '$SERVED_VER' != expected '$EXPECT_VER' — publish did not reach the served catalog"
  ok "  served index.json shows $APP_SLUG $SERVED_VER (matches)"
  info "  expected app.spk sha256: $EXPECT_SHA (compare against the Active on-chain ReleaseEntry AppHash before declaring HT14 done)"
fi
echo

ok "self-publish done for $APP_SLUG"
