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
#     [--receipt-dir <durable-dir>]    # required: retain verified stage/promote receipts
#     [--revoke-stale --expected-stale-pda <PDA> ...]
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
RECEIPT_DIR=""
STAGE_RECEIPT=""
PROMOTE_RECEIPT=""
DRY_RUN=false
REVOKE_STALE=false
EXPECTED_STALE_PDAS=()
STORE_URL="${MELUSINA_STORE_URL:-https://bazaar.melusina-os.org}"
STORE_DOMAIN="${MELUSINA_STORE_DOMAIN:-bazaar.melusina-os.org}"
STORE_LICENSE_MINT="${MELUSINA_STORE_LICENSE_MINT:-35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN}"
# The core-app-team Squads vault's master-NFT ATA — constant across every app
# (all apps share master mint B7Bby… + vault 3jfN9rc…, so the ATA is fixed).
# revoke_release_entry's authority-owns-master constraint keys on it.
MASTER_NFT_ATA="${MELUSINA_MASTER_NFT_ATA:-EA2FEHzhg4ZunhchFhcBMjaVtTh3pGkEy2SG6FEmYepn}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keys)         KEYS_DIR="$2"; shift 2 ;;
    --bump)         BUMP="$2"; shift 2 ;;
    --skip)         SKIP="$2"; shift 2 ;;
    --catalog-path) CATALOG_PATH_OVERRIDE="$2"; shift 2 ;;
    --receipt-dir)  RECEIPT_DIR="$2"; shift 2 ;;
    --expected-stale-pda) EXPECTED_STALE_PDAS+=("$2"); shift 2 ;;
    --revoke-stale) REVOKE_STALE=true; shift ;;
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
if $REVOKE_STALE; then
  [[ -n "$RECEIPT_DIR" ]] || { echo "FATAL: --revoke-stale requires --receipt-dir so verified stage/promote receipts survive the ceremony" >&2; exit 2; }
  ((${#EXPECTED_STALE_PDAS[@]} > 0)) || { echo "FATAL: --revoke-stale requires one or more explicit --expected-stale-pda values" >&2; exit 2; }
  declare -A seen_expected=()
  for pda in "${EXPECTED_STALE_PDAS[@]}"; do
    [[ -n "$pda" && -z "${seen_expected[$pda]:-}" ]] || { echo "FATAL: duplicate or empty --expected-stale-pda: '$pda'" >&2; exit 2; }
    seen_expected[$pda]=1
  done
fi

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
if $REVOKE_STALE; then
  info "Expected stale Active ReleaseEntries: ${EXPECTED_STALE_PDAS[*]}"
fi
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

RPC_URL="${MELUSINA_STORE_RPC_URL:-${MELUSINA_RPC_URL:-}}"
[[ -n "$RPC_URL" ]] || fail "  MELUSINA_STORE_RPC_URL (or MELUSINA_RPC_URL) required for receipt verification"

# ---- Step 5: durable stage through POST /publish/stage (sealed-v3) -----------
# The 1.0.5 store enforces the two-phase contract: the candidate MUST be
# durably staged (POST /publish/stage → signed StageReceipt) BEFORE the
# activation POST /publish, which looks the staged candidate up by its
# appId/appHash/releaseHash tuple. A bare promote against 1.0.5 is refused
# with "HTTP 409 check=stage: candidate was not durably staged before
# activation" (hit + fixed 2026-07-15, welcome-pearl 0.1.23). Keep the
# stage as a distinct durable boundary: revoking an old Active before this
# receipt exists can create a serving gap if the candidate cannot be staged.
step 5 "durably stage via $STORE_URL/publish/stage"
SUBMIT_BIN="$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar/bin/submit"
if [[ ! -x "$SUBMIT_BIN" ]]; then
  info "  building submit client"
  $DRY_RUN || (cd "$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar" && \
    mkdir -p bin && go build -o bin/submit ./cmd/submit) \
    || fail "  submit-build failed"
fi
if $DRY_RUN; then
  info "  DRY RUN — would durably stage $CAT_PATH/{app.spk,metadata.json,RELEASE.json} via $STORE_URL/publish/stage"
else
  submit_common=(
    --store "$STORE_URL"
    --spk "$CAT_PATH/app.spk"
    --metadata "$CAT_PATH/metadata.json"
    --release "$CAT_PATH/RELEASE.json"
    --publisher-key "$KEYS_DIR/publisher.key.json"
    --store-pubkey "$KEYS_DIR/store-pubkey.json"
    --license-mint "$STORE_LICENSE_MINT"
    --domain "$STORE_DOMAIN"
    --rpc-url "$RPC_URL"
    --timeout 480s
  )
  if $REVOKE_STALE; then
    mkdir -p "$RECEIPT_DIR" || fail "  could not create receipt directory $RECEIPT_DIR"
    STAGE_RECEIPT="$RECEIPT_DIR/$APP_SLUG-stage-receipt.json"
    PROMOTE_RECEIPT="$RECEIPT_DIR/$APP_SLUG-promote-receipt.json"
    [[ ! -e "$STAGE_RECEIPT" && ! -e "$PROMOTE_RECEIPT" ]] || fail "  refusing to overwrite existing ceremony receipt(s) in $RECEIPT_DIR"
  fi
  stage_args=(-stage)
  [[ -z "$STAGE_RECEIPT" ]] || stage_args+=(--receipt-out "$STAGE_RECEIPT")
  "$SUBMIT_BIN" "${submit_common[@]}" "${stage_args[@]}" \
    || fail "  stage rejected by $STORE_URL/publish/stage — see output above (check=... names the failing gate)"
  [[ -z "${STAGE_RECEIPT:-}" || -s "$STAGE_RECEIPT" ]] || fail "  verified stage receipt was not retained at $STAGE_RECEIPT"
fi
echo

# ---- Step 5b: revoke stale Active ReleaseEntries (OPT-IN, after stage) -------
# Apps have no atomic on-chain supersede. The store accepts promotion only when
# no different Active ReleaseEntry remains for the app, but the old entry must
# stay Active until the candidate has a durable StageReceipt. The safe order is
# ceremony/register -> durable stage -> revoke stale entries -> promote.
if $REVOKE_STALE && ! skip_step ceremony && ! $DRY_RUN; then
  step 5b "revoke stale Active ReleaseEntries after durable stage (--revoke-stale)"
  NEW_PDA="$(python3 -c 'import json;print(json.load(open("'"$CAT_PATH"'/RELEASE.json")).get("releaseEntryPda",""))' 2>/dev/null || true)"
  [[ -n "$NEW_PDA" ]] || fail "  --revoke-stale: could not read the just-registered releaseEntryPda from $CAT_PATH/RELEASE.json"
  LIST_BIN="$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar/bin/list-active-releases"
  if [[ ! -x "$LIST_BIN" ]]; then
    info "  building list-active-releases"
    (cd "$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar" && mkdir -p bin && go build -o bin/list-active-releases ./cmd/list-active-releases) \
      || fail "  list-active-releases build failed"
  fi
  ACTIVE_JSON="$(mktemp)"
  ACTIVE_PDAS="$(mktemp)"
  trap 'rm -f "${ACTIVE_JSON:-}" "${ACTIVE_PDAS:-}"' EXIT
  "$LIST_BIN" -rpc-url "$RPC_URL" -known-pda "$NEW_PDA" >"$ACTIVE_JSON" \
    || fail "  Active ReleaseEntry enumeration failed; refusing to revoke without a complete chain view"
  python3 - "$NEW_PDA" <"$ACTIVE_JSON" >"$ACTIVE_PDAS" <<'PY' \
    || fail "  Active ReleaseEntry enumeration was malformed; refusing to revoke"
import json, sys
new_pda = sys.argv[1]
seen = set()
for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    entry = json.loads(raw)
    pda = entry.get("pda")
    if not isinstance(pda, str) or not pda or pda in seen:
        raise SystemExit("invalid or duplicate Active ReleaseEntry PDA")
    seen.add(pda)
if new_pda not in seen:
    raise SystemExit("just-registered ReleaseEntry is not Active")
for pda in sorted(seen - {new_pda}):
    print(pda)
PY
  mapfile -t ACTUAL_STALE_PDAS <"$ACTIVE_PDAS"
  mapfile -t EXPECTED_STALE_SORTED < <(printf '%s\n' "${EXPECTED_STALE_PDAS[@]}" | LC_ALL=C sort)
  [[ "${ACTUAL_STALE_PDAS[*]}" == "${EXPECTED_STALE_SORTED[*]}" ]] \
    || fail "  Active ReleaseEntry set differs from explicit --expected-stale-pda allowlist; refusing to revoke"
  for pda in "${EXPECTED_STALE_SORTED[@]}"; do
    info "  revoking stale Active ReleaseEntry $pda"
    STALE_RELEASE_ENTRY_PDA="$pda" MASTER_NFT_ATA="$MASTER_NFT_ATA" MELUSINA_RPC_URL="$RPC_URL" \
      MELUSINA_PUBLISHER_KEYPAIR="$KEYS_DIR/publisher.json" \
      MELUSINA_REVIEWER1_KEYPAIR="$KEYS_DIR/reviewer-1.json" \
      MELUSINA_REVIEWER2_KEYPAIR="$KEYS_DIR/reviewer-2.json" \
      MELUSINA_SQUADS_CONFIG="$KEYS_DIR/core-app-team-squads.json" \
      "$STATIC_STORE_ROOT/scripts/revoke-release-ceremony.sh" "$APP_SLUG-revoke" \
      || fail "  revoke of stale $pda failed"
  done
  echo
fi

# ---- Step 5c: promote the already staged candidate ---------------------------
step 5c "promote staged candidate via $STORE_URL/publish"
if $DRY_RUN; then
  info "  DRY RUN — would promote the already staged tuple via $STORE_URL/publish"
else
  promote_args=()
  [[ -z "$PROMOTE_RECEIPT" ]] || promote_args+=(--receipt-out "$PROMOTE_RECEIPT")
  "$SUBMIT_BIN" "${submit_common[@]}" "${promote_args[@]}" \
    || fail "  promote rejected by $STORE_URL/publish — see output above (check=... names the failing gate)"
  [[ -z "${PROMOTE_RECEIPT:-}" || -s "$PROMOTE_RECEIPT" ]] || fail "  verified promotion receipt was not retained at $PROMOTE_RECEIPT"
fi
echo

# The promotion receipt proves the store accepted this tuple. Re-read the
# chain independently before calling it live: after a revoke run the new PDA
# must be the ONE Active entry and must pin this exact RELEASE.json tree hash.
if $REVOKE_STALE && ! skip_step ceremony && ! $DRY_RUN; then
  step 5d "independently assert exactly one Active ReleaseEntry after promote"
  EXPECTED_APP_HASH="$(python3 -c 'import json; print(json.load(open("'"$CAT_PATH"'/RELEASE.json"))["appHash"])')"
  FINAL_ACTIVE_JSON="$(mktemp)"
  trap 'rm -f "${ACTIVE_JSON:-}" "${ACTIVE_PDAS:-}" "${FINAL_ACTIVE_JSON:-}"' EXIT
  "$LIST_BIN" -rpc-url "$RPC_URL" -known-pda "$NEW_PDA" >"$FINAL_ACTIVE_JSON" \
    || fail "  final Active ReleaseEntry enumeration failed"
  python3 - "$NEW_PDA" "$EXPECTED_APP_HASH" <"$FINAL_ACTIVE_JSON" <<'PY' \
    || fail "  post-promote chain state is not exactly the new Active ReleaseEntry"
import json, sys
want_pda, want_hash = sys.argv[1:]
entries = []
for raw in sys.stdin:
    raw = raw.strip()
    if raw:
        entries.append(json.loads(raw))
if len(entries) != 1 or entries[0].get("pda") != want_pda or entries[0].get("appHash", "").lower() != want_hash.lower():
    raise SystemExit("expected exactly the promoted PDA with the RELEASE.json appHash")
PY
  ok "  exactly one Active ReleaseEntry remains and it pins $EXPECTED_APP_HASH"
  echo
fi

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
  SERVED_PACKAGE_ID="$(python3 -c "
import json,sys
d=json.loads(sys.argv[1])
apps=d.get('apps', d if isinstance(d,list) else [])
for a in apps:
    if a.get('appId')=='$APP_ID':
        print(a.get('packageId') or '')
        break
" "$SERVED_JSON" 2>/dev/null || true)"
  [[ "$SERVED_VER" == "$EXPECT_VER" ]] \
    || fail "  served index.json version '$SERVED_VER' != expected '$EXPECT_VER' — publish did not reach the served catalog"
  [[ "$SERVED_PACKAGE_ID" == "${EXPECT_SHA:0:32}" ]] \
    || fail "  served index.json packageId '$SERVED_PACKAGE_ID' != expected '${EXPECT_SHA:0:32}'"
  SERVED_SHA="$(curl -fsS --max-time 120 "$STORE_URL/packages/$SERVED_PACKAGE_ID" | sha256sum | awk '{print $1}')" \
    || fail "  could not fetch the served package for SHA-256 verification"
  [[ "$SERVED_SHA" == "$EXPECT_SHA" ]] \
    || fail "  served package SHA-256 '$SERVED_SHA' != expected '$EXPECT_SHA'"
  ok "  served index.json shows $APP_SLUG $SERVED_VER (matches)"
  ok "  served package SHA-256 $SERVED_SHA matches the clean artifact"
fi
echo

ok "self-publish done for $APP_SLUG"
