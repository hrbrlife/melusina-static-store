#!/usr/bin/env bash
#
# self-publish.sh — serialized two-phase PUBLISH-TZAR app driver.
#
# Default execution is deliberately PRE-CHAIN: build a clean candidate, stage
# it privately with a purpose-bound POST+/publish/stage envelope, verify and
# save the signed stage receipt, then stop. Promotion uses a separately signed
# POST+/publish envelope. New-release chain mutation is reachable only with an
# explicit Riker authorization receipt; exact-current G2 migration uses
# --promote-existing-active and performs no app chain write.
#
# Usage:
#   self-publish.sh <app-source-dir> --keys <dir> [--catalog-path <dir>] \
#     [--bump patch|minor|major|none] [--promote-existing-active] \
#     [--new-release-authorized <riker-receipt>] [--dry-run]
#
# The driver never writes dist-publish, calls sync-catalog.sh, revokes a
# release, installs a store, or treats dry-run as proof.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATIC_STORE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"

APP_DIR=""
KEYS_DIR=""
CATALOG_PATH_OVERRIDE=""
BUMP="none"
PROMOTE_EXISTING=false
AUTHORIZATION_RECEIPT=""
DRY_RUN=false
STORE_URL="${MELUSINA_STORE_URL:-https://bazaar.melusina-os.org}"
STORE_DOMAIN="${MELUSINA_STORE_DOMAIN:-bazaar.melusina-os.org}"
STORE_LICENSE_MINT="${MELUSINA_STORE_LICENSE_MINT:-35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keys) KEYS_DIR="$2"; shift 2 ;;
    --catalog-path) CATALOG_PATH_OVERRIDE="$2"; shift 2 ;;
    --bump) BUMP="$2"; shift 2 ;;
    --promote-existing-active) PROMOTE_EXISTING=true; shift ;;
    --new-release-authorized) AUTHORIZATION_RECEIPT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) [[ -z "$APP_DIR" ]] || { echo "unknown argument: $1" >&2; exit 2; }; APP_DIR="$1"; shift ;;
  esac
done

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
info() { printf '[INFO] %s\n' "$*"; }
need_file() { [[ -f "$1" ]] || fail "required file missing: $1"; }

[[ -n "$APP_DIR" && -d "$APP_DIR" ]] || fail "app source directory is required"
[[ -n "$KEYS_DIR" && -d "$KEYS_DIR" ]] || fail "--keys directory is required"
case "$BUMP" in patch|minor|major|none) ;; *) fail "--bump must be patch, minor, major, or none" ;; esac
if $PROMOTE_EXISTING && [[ -n "$AUTHORIZATION_RECEIPT" ]]; then
  fail "choose exact-current --promote-existing-active OR authorized new release, never both"
fi
for name in publisher.key.json store-pubkey.json; do need_file "$KEYS_DIR/$name"; done
if [[ -n "$AUTHORIZATION_RECEIPT" ]]; then
  need_file "$AUTHORIZATION_RECEIPT"
  for name in publisher.json reviewer-1.json reviewer-2.json core-app-team-squads.json; do need_file "$KEYS_DIR/$name"; done
  python3 - "$AUTHORIZATION_RECEIPT" <<'PY' || fail "invalid Riker ceremony authorization receipt"
import json,sys
d=json.load(open(sys.argv[1], encoding="utf-8"))
assert d.get("schema") == "melusina-riker-app-ceremony-authorization-v1"
assert d.get("authorized") is True
assert isinstance(d.get("authorizedAt"), str) and d["authorizedAt"]
assert isinstance(d.get("appId"), str) and d["appId"]
PY
fi

# One workstation driver owns the app ceremony/promotion seam at a time. The
# service has its own process/nonce locks; this lock governs human ceremony
# ordering and makes the PUBLISH-TZAR contract explicit.
LOCK_PATH="${MELUSINA_PUBLISH_TZAR_LOCK:-/tmp/melusina-publish-tzar.lock}"
exec 9>"$LOCK_PATH"
flock -n 9 || fail "another PUBLISH-TZAR driver holds $LOCK_PATH"

cd "$APP_DIR"
APP_SLUG="$(basename "$APP_DIR")"
if [[ "$BUMP" != none ]]; then
  if $DRY_RUN; then
    info "DRY: would version-bump $BUMP, then stop for source review+commit"
  else
    "$SCRIPT_DIR/version-bump.sh" "$APP_DIR" "$BUMP"
    info "STOP PRE-BUILD: review and commit the version bump, then rerun with --bump none"
  fi
  exit 0
fi
if $DRY_RUN; then
  info "DRY: would require a clean committed source and build one candidate; dry-run emits no publish proof"
  exit 0
fi
need_file "$SCRIPT_DIR/pack-app-candidate.sh"
CANDIDATE_RECEIPT="${MELUSINA_CANDIDATE_RECEIPT:-/tmp/melusina-$APP_SLUG-candidate.json}"
"$SCRIPT_DIR/pack-app-candidate.sh" "$APP_DIR" --receipt-out "$CANDIDATE_RECEIPT"
need_file "$APP_DIR/app.spk"

CAT_PATH="$CATALOG_PATH_OVERRIDE"
if [[ -z "$CAT_PATH" ]]; then
  command -v spk >/dev/null 2>&1 || fail "spk CLI is required to resolve appId"
  APP_ID="$(spk verify "$APP_DIR/app.spk" 2>/dev/null | sed -n 's/.*"appId": "\([^"]*\)".*/\1/p' | head -1)"
  [[ -n "$APP_ID" ]] || fail "could not extract appId from app.spk"
  mapfile -t matches < <(grep -rl --include=metadata.json "\"appId\": *\"$APP_ID\"" "$STATIC_STORE_ROOT/packages" 2>/dev/null || true)
  [[ ${#matches[@]} -eq 1 ]] || fail "expected exactly one catalog slot for appId=$APP_ID; pass --catalog-path only for a governed first publish"
  CAT_PATH="${matches[0]%/metadata.json}"
fi
[[ "$CAT_PATH" == "$STATIC_STORE_ROOT"/packages/* ]] || fail "catalog path must be inside static_store/packages"

# The exact candidate above is used for both private stage and any later
# ceremony; no rebuild is permitted between these gates.
if $PROMOTE_EXISTING; then
  PRESERVE_EXISTING_RELEASE=1 "$SCRIPT_DIR/stage-into-catalog.sh" "$APP_DIR/app.spk" "$CAT_PATH"
else
  "$SCRIPT_DIR/stage-into-catalog.sh" "$APP_DIR/app.spk" "$CAT_PATH"
fi
for name in app.spk metadata.json RELEASE.json; do need_file "$CAT_PATH/$name"; done

RPC_URL="${MELUSINA_STORE_RPC_URL:-${MELUSINA_RPC_URL:-}}"
[[ -n "$RPC_URL" ]] || fail "MELUSINA_STORE_RPC_URL or MELUSINA_RPC_URL is required"
SUBMIT_BIN="$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar/bin/submit"
if [[ ! -x "$SUBMIT_BIN" ]]; then
  (cd "$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar" && mkdir -p bin && go build -o bin/submit ./cmd/submit)
fi
RECEIPT_DIR="${MELUSINA_PUBLISH_RECEIPT_DIR:-/tmp/melusina-publish-receipts/$APP_SLUG}"
mkdir -p "$RECEIPT_DIR"
chmod 700 "$RECEIPT_DIR"
STAGE_RECEIPT="$RECEIPT_DIR/$APP_SLUG-stage.json"
PROMOTE_RECEIPT="$RECEIPT_DIR/$APP_SLUG-promote.json"

submit_common=(
  --store "$STORE_URL" --spk "$CAT_PATH/app.spk"
  --metadata "$CAT_PATH/metadata.json" --release "$CAT_PATH/RELEASE.json"
  --publisher-key "$KEYS_DIR/publisher.key.json" --store-pubkey "$KEYS_DIR/store-pubkey.json"
  --license-mint "$STORE_LICENSE_MINT" --domain "$STORE_DOMAIN"
  --rpc-url "$RPC_URL" --timeout 480s
)

# Envelope S is generated inside this invocation and is valid only at the
# stage route. Successful return includes local verification of the store's
# signed stage receipt against current on-chain store authority.
"$SUBMIT_BIN" "${submit_common[@]}" --stage --receipt-out "$STAGE_RECEIPT"
info "private stage verified: $STAGE_RECEIPT"

if ! $PROMOTE_EXISTING && [[ -z "$AUTHORIZATION_RECEIPT" ]]; then
  info "STOP PRE-CHAIN: candidate is staged; obtain Riker ceremony authorization or rerun with --promote-existing-active for the exact-current G2 path"
  exit 0
fi

if [[ -n "$AUTHORIZATION_RECEIPT" ]]; then
  APP_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["appId"])' "$CAT_PATH/metadata.json")"
  AUTH_APP_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["appId"])' "$AUTHORIZATION_RECEIPT")"
  [[ "$AUTH_APP_ID" == "$APP_ID" ]] || fail "authorization appId does not match staged candidate"
  info "AUTHORIZED CHAIN CEREMONY: $AUTHORIZATION_RECEIPT"
  CEREMONY_VER="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("marketingVersion") or d.get("version") or "")' "$CAT_PATH/metadata.json")"
  APP_CATALOG_PATH="$CAT_PATH" APP_SLUG="$APP_SLUG" MELUSINA_VERSION="$CEREMONY_VER" \
    MELUSINA_PUBLISHER_KEYPAIR="$KEYS_DIR/publisher.json" \
    MELUSINA_REVIEWER1_KEYPAIR="$KEYS_DIR/reviewer-1.json" \
    MELUSINA_REVIEWER2_KEYPAIR="$KEYS_DIR/reviewer-2.json" \
    MELUSINA_SQUADS_CONFIG="$KEYS_DIR/core-app-team-squads.json" \
    "$SCRIPT_DIR/pearl-app-ceremony.sh"
else
  info "EXACT-CURRENT: no app chain write; existing Active ReleaseEntry remains authoritative"
fi

# Envelope P is freshly generated here and is valid only at /publish. It never
# reuses the stage nonce or purpose.
"$SUBMIT_BIN" "${submit_common[@]}" --receipt-out "$PROMOTE_RECEIPT"
"$SUBMIT_BIN" --verify-receipt "$PROMOTE_RECEIPT" \
  --store "$STORE_URL" --license-mint "$STORE_LICENSE_MINT" \
  --domain "$STORE_DOMAIN" --rpc-url "$RPC_URL"

APP_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["appId"])' "$CAT_PATH/metadata.json")"
POINTER_URL="$STORE_URL/apps/pointers/$APP_ID.json"
curl -fsS --max-time 30 "$POINTER_URL" -o "$RECEIPT_DIR/$APP_SLUG-pointer.json"
python3 - "$PROMOTE_RECEIPT" "$RECEIPT_DIR/$APP_SLUG-pointer.json" <<'PY' || fail "served pointer differs from verified promotion receipt"
import json,sys
r=json.load(open(sys.argv[1], encoding="utf-8"))
p=json.load(open(sys.argv[2], encoding="utf-8"))
assert r["catalog"] == p
assert r["stage"]["stageId"] == r["rollout"]["currentStageId"] == p["stageId"]
assert r["appHash"] == p["appHash"]
PY
info "PROMOTED + PULL-VERIFIED: $PROMOTE_RECEIPT"
