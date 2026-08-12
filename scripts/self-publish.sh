#!/usr/bin/env bash
#
# self-publish.sh — serialized two-phase PUBLISH-TZAR app driver.
#
# Default execution is deliberately PRE-CHAIN: build a clean candidate, stage
# it privately with a purpose-bound POST+/publish/stage envelope, verify and
# save the signed stage receipt, then stop. Promotion uses a separately signed
# POST+/publish envelope. This repository exposes no app-chain writer:
# exact-current G2 migration uses --promote-existing-active and performs no app
# chain write; a new ReleaseEntry must be finalized by the separate governed
# ceremony before its exact bytes enter this stage/promote driver.
#
# Usage:
#   self-publish.sh <app-source-dir> --keys <dir> [--catalog-path <dir>] \
#     [--bump patch|minor|major|none] [--promote-existing-active] [--dry-run]
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

# Canonicalize before the later cd, and reject every symlink component. This
# keeps app/key/catalog references stable for the whole invocation.
canonical_dir() {
  python3 - "$1" <<'PY'
import os, stat, sys
p=os.path.abspath(sys.argv[1])
cur=os.path.sep
for part in [x for x in p.split(os.path.sep) if x]:
    cur=os.path.join(cur, part)
    st=os.lstat(cur)
    if stat.S_ISLNK(st.st_mode):
        raise SystemExit(f"symlink path component refused: {cur}")
if not os.path.isdir(p):
    raise SystemExit(f"not a directory: {p}")
print(os.path.realpath(p))
PY
}
APP_DIR="$(canonical_dir "$APP_DIR")" || fail "app source path is not canonical"
KEYS_DIR="$(canonical_dir "$KEYS_DIR")" || fail "key path is not canonical"
if [[ -n "$CATALOG_PATH_OVERRIDE" ]]; then
  CATALOG_PATH_OVERRIDE="$(canonical_dir "$CATALOG_PATH_OVERRIDE")" || fail "catalog path is not canonical"
fi
for name in publisher.key.json store-pubkey.json; do need_file "$KEYS_DIR/$name"; done

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
CAT_PATH="$CATALOG_PATH_OVERRIDE"
CANDIDATE_SPK=""
STAGE_METADATA_PATH=""
if $PROMOTE_EXISTING; then
  # An Active ReleaseEntry already fixes the exact SPK and metadata tuple. Do
  # not rebuild it: rebuilding can produce bytes that are valid but different
  # from the governed release. Re-stage the committed tuple and let the Store,
  # on-chain entry, runtime contract, and signed receipts verify it.
  [[ -n "$CAT_PATH" ]] || fail "--promote-existing-active requires --catalog-path"
  for name in app.spk metadata.json RELEASE.json; do need_file "$CAT_PATH/$name"; done
  git -C "$APP_DIR" status --porcelain --untracked-files=normal | grep -q '^' && \
    fail "source tree is dirty before exact-current promotion"
  CANDIDATE_SPK="$CAT_PATH/app.spk"
  STAGE_METADATA_PATH="$CAT_PATH/metadata.json"
else
  CANDIDATE_RECEIPT="${MELUSINA_CANDIDATE_RECEIPT:-/tmp/melusina-$APP_SLUG-candidate.json}"
  # Most app sources keep metadata at their root. A governed catalog release
  # may instead own its metadata in the declared catalog slot (as MerMail does).
  # Do not synthesize or copy metadata: pack and later stage tracked bytes.
  SOURCE_METADATA_PATH="$APP_DIR/metadata.json"
  if [[ ! -f "$SOURCE_METADATA_PATH" && -n "$CATALOG_PATH_OVERRIDE" ]]; then
    SOURCE_METADATA_PATH="$CATALOG_PATH_OVERRIDE/metadata.json"
  fi
  need_file "$SOURCE_METADATA_PATH"
  CANDIDATE_METADATA_OUT="$(mktemp "/tmp/melusina-$APP_SLUG-candidate-metadata.XXXXXX")"
  "$SCRIPT_DIR/pack-app-candidate.sh" "$APP_DIR" \
    --metadata "$SOURCE_METADATA_PATH" --metadata-out "$CANDIDATE_METADATA_OUT" \
    --receipt-out "$CANDIDATE_RECEIPT"
  need_file "$APP_DIR/app.spk"
  CANDIDATE_SPK="$APP_DIR/app.spk"
  STAGE_METADATA_PATH="$SOURCE_METADATA_PATH"
  if [[ -s "$CANDIDATE_METADATA_OUT" ]]; then
    STAGE_METADATA_PATH="$CANDIDATE_METADATA_OUT"
  fi
  if [[ -z "$CAT_PATH" ]]; then
    command -v spk >/dev/null 2>&1 || fail "spk CLI is required to resolve appId"
    APP_ID="$(spk verify "$CANDIDATE_SPK" 2>/dev/null | sed -n 's/.*"appId": "\([^"]*\)".*/\1/p' | head -1)"
    [[ -n "$APP_ID" ]] || fail "could not extract appId from app.spk"
    mapfile -t matches < <(grep -rl --include=metadata.json "\"appId\": *\"$APP_ID\"" "$STATIC_STORE_ROOT/packages" 2>/dev/null || true)
    [[ ${#matches[@]} -eq 1 ]] || fail "expected exactly one catalog slot for appId=$APP_ID; pass --catalog-path only for a governed first publish"
    CAT_PATH="$(canonical_dir "${matches[0]%/metadata.json}")" || fail "catalog path is not canonical"
  fi
fi
PACKAGES_ROOT="$(canonical_dir "$STATIC_STORE_ROOT/packages")" || fail "packages root is not canonical"
case "$CAT_PATH" in "$PACKAGES_ROOT"/*) ;; *) fail "catalog path must resolve inside static_store/packages" ;; esac

# The exact candidate above is used for both private stage and any later
# ceremony; no rebuild is permitted between these gates.
if $PROMOTE_EXISTING; then
  SOURCE_METADATA_PATH="$STAGE_METADATA_PATH" PRESERVE_EXISTING_RELEASE=1 \
    "$SCRIPT_DIR/stage-into-catalog.sh" "$CANDIDATE_SPK" "$CAT_PATH"
else
  SOURCE_METADATA_PATH="$STAGE_METADATA_PATH" \
    "$SCRIPT_DIR/stage-into-catalog.sh" "$CANDIDATE_SPK" "$CAT_PATH"
fi
for name in app.spk metadata.json RELEASE.json; do need_file "$CAT_PATH/$name"; done

# A bound runtime contract is part of the Store's staged candidate identity.
# Pass its exact bytes to both the private-stage and promotion requests; without
# it the client derives a different StageID than the Store and correctly rejects
# the otherwise valid signed receipt.
mapfile -t runtime_contract_fields < <(
  python3 - "$CAT_PATH/RELEASE.json" <<'PY'
import json, sys
release = json.load(open(sys.argv[1], encoding="utf-8"))
print(release.get("runtimeContractSchema", ""))
print(release.get("runtimeContractSha256", ""))
PY
)
RUNTIME_CONTRACT_SCHEMA="${runtime_contract_fields[0]:-}"
RUNTIME_CONTRACT_SHA256="${runtime_contract_fields[1]:-}"
RUNTIME_CONTRACT_ARGS=()
if [[ -z "$RUNTIME_CONTRACT_SCHEMA" && -z "$RUNTIME_CONTRACT_SHA256" ]]; then
  [[ ! -e "$CAT_PATH/RUNTIME-CONTRACT.json" ]] || fail "unbound RELEASE.json must not retain RUNTIME-CONTRACT.json"
elif [[ "$RUNTIME_CONTRACT_SCHEMA" != "melusina-app-runtime-contract-v1" || ! "$RUNTIME_CONTRACT_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
  fail "RELEASE.json has an invalid runtime-contract binding"
else
  need_file "$CAT_PATH/RUNTIME-CONTRACT.json"
  ACTUAL_RUNTIME_CONTRACT_SHA256="$(sha256sum "$CAT_PATH/RUNTIME-CONTRACT.json" | cut -d' ' -f1)"
  [[ "${ACTUAL_RUNTIME_CONTRACT_SHA256,,}" == "${RUNTIME_CONTRACT_SHA256,,}" ]] || \
    fail "RUNTIME-CONTRACT.json sha256 does not match RELEASE.json"
  RUNTIME_CONTRACT_ARGS=(--runtime-contract "$CAT_PATH/RUNTIME-CONTRACT.json")
fi

RPC_URL="${MELUSINA_STORE_RPC_URL:-${MELUSINA_RPC_URL:-}}"
[[ -n "$RPC_URL" ]] || fail "MELUSINA_STORE_RPC_URL or MELUSINA_RPC_URL is required"
SUBMIT_BIN="$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar/bin/submit"
if [[ ! -x "$SUBMIT_BIN" ]]; then
  (cd "$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar" && mkdir -p bin && go build -o bin/submit ./cmd/submit)
fi
ACTIVE_BIN="$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar/bin/list-active-releases"
if [[ ! -x "$ACTIVE_BIN" ]]; then
  (cd "$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar" && mkdir -p bin && go build -o bin/list-active-releases ./cmd/list-active-releases)
fi
RECEIPT_DIR="${MELUSINA_PUBLISH_RECEIPT_DIR:-/tmp/melusina-publish-receipts/$APP_SLUG}"
mkdir -p "$RECEIPT_DIR"
chmod 700 "$RECEIPT_DIR"
STAGE_RECEIPT="$RECEIPT_DIR/$APP_SLUG-stage.json"
PROMOTE_RECEIPT="$RECEIPT_DIR/$APP_SLUG-promote.json"
ACTIVE_BEFORE="$RECEIPT_DIR/$APP_SLUG-active-before.jsonl"
ACTIVE_AFTER="$RECEIPT_DIR/$APP_SLUG-active-after.jsonl"

submit_common=(
  --store "$STORE_URL" --spk "$CAT_PATH/app.spk"
  --metadata "$CAT_PATH/metadata.json" --release "$CAT_PATH/RELEASE.json"
  "${RUNTIME_CONTRACT_ARGS[@]}"
  --publisher-key "$KEYS_DIR/publisher.key.json" --store-pubkey "$KEYS_DIR/store-pubkey.json"
  --license-mint "$STORE_LICENSE_MINT" --domain "$STORE_DOMAIN"
  --rpc-url "$RPC_URL" --timeout 480s
)

# Envelope S is generated inside this invocation and is valid only at the
# stage route. Successful return includes local verification of the store's
# signed stage receipt against current on-chain store authority.
"$SUBMIT_BIN" "${submit_common[@]}" --stage --receipt-out "$STAGE_RECEIPT"
info "private stage verified: $STAGE_RECEIPT"

if ! $PROMOTE_EXISTING; then
  info "STOP PRE-CHAIN: candidate is staged; this repository has no app-chain writer. Finalize any new ReleaseEntry externally, then restage its exact governed bytes; use --promote-existing-active only for an already-Active exact-current release"
  exit 0
fi

info "EXACT-CURRENT: no app chain write; existing Active ReleaseEntry remains authoritative"
KNOWN_RELEASE_PDA="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("releaseEntryPda") or "")' "$CAT_PATH/RELEASE.json")"
[[ -n "$KNOWN_RELEASE_PDA" ]] || fail "exact-current release has no releaseEntryPda"
"$ACTIVE_BIN" -rpc-url "$RPC_URL" -known-pda "$KNOWN_RELEASE_PDA" | LC_ALL=C sort >"$ACTIVE_BEFORE"
[[ "$(wc -l <"$ACTIVE_BEFORE" | tr -d '[:space:]')" == "1" ]] || fail "exact-current requires exactly one Active ReleaseEntry before promotion"

# Envelope P is freshly generated here and is valid only at /publish. It never
# reuses the stage nonce or purpose.
"$SUBMIT_BIN" "${submit_common[@]}" --receipt-out "$PROMOTE_RECEIPT"
"$SUBMIT_BIN" --verify-receipt "$PROMOTE_RECEIPT" \
  --store "$STORE_URL" --license-mint "$STORE_LICENSE_MINT" \
  --domain "$STORE_DOMAIN" --rpc-url "$RPC_URL"
"$ACTIVE_BIN" -rpc-url "$RPC_URL" -known-pda "$KNOWN_RELEASE_PDA" | LC_ALL=C sort >"$ACTIVE_AFTER"
[[ "$(wc -l <"$ACTIVE_AFTER" | tr -d '[:space:]')" == "1" ]] || fail "exact-current requires exactly one Active ReleaseEntry after promotion"
cmp -s "$ACTIVE_BEFORE" "$ACTIVE_AFTER" || fail "Active ReleaseEntry set changed during exact-current promotion"

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
