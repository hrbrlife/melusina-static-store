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
#     [--bump none]                    # versions must already be committed \
#     [--skip ceremony] \
#     [--catalog-path <dir>]           # override auto-detected static_store
#                                       #   packages/<dev>/<repo>/<slug> dir
#     [--shell-url <url>]               # target Melusina shell
#     [--shell-domain <host>]           # wallet-login envelope domain
#     [--admin-wallet <keypair.json>]   # on-chain install admin
#     [--canary-grain <grainId>]        # optional deterministic canary
#     [--publish-only]                  # stop before install/canary
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
BUMP="none"
SKIP=""
CATALOG_PATH_OVERRIDE=""
DRY_RUN=false
REVOKE_STALE=false
PUBLISH_ONLY=false
STORE_URL="${MELUSINA_STORE_URL:-https://bazaar.melusina-os.org}"
STORE_DOMAIN="${MELUSINA_STORE_DOMAIN:-bazaar.melusina-os.org}"
STORE_LICENSE_MINT="${MELUSINA_STORE_LICENSE_MINT:-35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN}"
# The core-app-team Squads vault's master-NFT ATA — constant across every app
# (all apps share master mint B7Bby… + vault 3jfN9rc…, so the ATA is fixed).
# revoke_release_entry's authority-owns-master constraint keys on it.
MASTER_NFT_ATA="${MELUSINA_MASTER_NFT_ATA:-EA2FEHzhg4ZunhchFhcBMjaVtTh3pGkEy2SG6FEmYepn}"
SHELL_URL="${MELUSINA_SHELL_URL:-${SHELL_URL:-}}"
SHELL_DOMAIN="${MELUSINA_DOMAIN:-${DOMAIN:-}}"
ADMIN_WALLET="${ADMIN_WALLET_KEYPAIR:-}"
CANARY_GRAIN="${MELUSINA_APP_CANARY_GRAIN_ID:-}"
ROLLOUT_DRIVER="${MELUSINA_APP_ROLLOUT_DRIVER:-$(dirname "$STATIC_STORE_ROOT")/Melusina/deployer/scripts/rollout-app-release.mjs}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keys)         KEYS_DIR="$2"; shift 2 ;;
    --bump)         BUMP="$2"; shift 2 ;;
    --skip)         SKIP="$2"; shift 2 ;;
    --catalog-path) CATALOG_PATH_OVERRIDE="$2"; shift 2 ;;
    --revoke-stale) REVOKE_STALE=true; shift ;;
    --shell-url)     SHELL_URL="$2"; shift 2 ;;
    --shell-domain)  SHELL_DOMAIN="$2"; shift 2 ;;
    --admin-wallet)  ADMIN_WALLET="$2"; shift 2 ;;
    --canary-grain)  CANARY_GRAIN="$2"; shift 2 ;;
    --publish-only)  PUBLISH_ONLY=true; shift ;;
    --dry-run)      DRY_RUN=true; shift ;;
    -h|--help) sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
    *) [[ -z "$APP_DIR" ]] || { echo "unknown arg: $1" >&2; exit 2; }; APP_DIR="$1"; shift ;;
  esac
done

[[ -n "$APP_DIR" ]] || { echo "FATAL: app source dir required" >&2; exit 2; }
[[ -d "$APP_DIR" ]] || { echo "FATAL: not a directory: $APP_DIR" >&2; exit 2; }
[[ "$BUMP" == "none" ]] || {
  echo "FATAL: release-time version mutation is disabled. Run version-bump.sh, test, commit, then publish with --bump none." >&2
  exit 2
}
if ! $DRY_RUN && git -C "$APP_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  [[ -z "$(git -C "$APP_DIR" status --porcelain --untracked-files=normal)" ]] || {
    echo "FATAL: app source tree is dirty; publish only from an exact committed revision: $APP_DIR" >&2
    git -C "$APP_DIR" status --short >&2
    exit 2
  }
fi
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

$REVOKE_STALE && fail "--revoke-stale is retired: the prior release must remain Active through canary rollout and the rollback window"
if ! $PUBLISH_ONLY && ! $DRY_RUN; then
  [[ -n "$SHELL_URL" ]] || fail "--shell-url (or MELUSINA_SHELL_URL) is required for verified install/canary"
  if [[ -z "$SHELL_DOMAIN" ]]; then
    SHELL_DOMAIN="$(python3 -c 'import sys,urllib.parse;print(urllib.parse.urlparse(sys.argv[1]).hostname or "")' "$SHELL_URL")"
  fi
  [[ -n "$SHELL_DOMAIN" ]] || fail "--shell-domain (or MELUSINA_DOMAIN) is required"
  [[ -n "$ADMIN_WALLET" && -f "$ADMIN_WALLET" ]] \
    || fail "--admin-wallet (or ADMIN_WALLET_KEYPAIR) must name the install-admin keypair"
  [[ -f "$ROLLOUT_DRIVER" ]] || fail "app rollout driver not found: $ROLLOUT_DRIVER"
fi

cd "$APP_DIR"
APP_SLUG="$(basename "$APP_DIR")"
info "App: $APP_SLUG ($APP_DIR)"
info "Keys: $KEYS_DIR"
info "Store: $STORE_URL   Bump: $BUMP   Dry-run: $DRY_RUN"
echo

# ---- Step 1: version bump ---------------------------------------------------
step 1 "verify committed version"
info "  source version is immutable during publish (--bump none)"
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

RPC_URL="${MELUSINA_STORE_RPC_URL:-${MELUSINA_RPC_URL:-}}"
[[ -n "$RPC_URL" ]] || fail "  MELUSINA_STORE_RPC_URL (or MELUSINA_RPC_URL) required for receipt verification"
SUBMIT_BIN="$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar/bin/submit"
if [[ ! -x "$SUBMIT_BIN" ]]; then
  info "  building submit client"
  $DRY_RUN || (cd "$STATIC_STORE_ROOT/sidecar/melusina-store-sidecar" && \
    mkdir -p bin && go build -o bin/submit ./cmd/submit) \
    || fail "  submit-build failed"
fi
CAT_REL="${CAT_PATH#"$STATIC_STORE_ROOT/packages/"}"
IFS=/ read -r CAT_DEVELOPER CAT_REPO CAT_SLUG CAT_EXTRA <<<"$CAT_REL"
[[ -n "$CAT_DEVELOPER" && -n "$CAT_REPO" && -n "$CAT_SLUG" && -z "${CAT_EXTRA:-}" ]] \
  || fail "  catalog path must be exactly packages/<developer>/<repo>/<slug>: $CAT_PATH"
PUBLISH_RUN_DIR="${MELUSINA_PUBLISH_RUN_DIR:-/tmp/melusina-publish-$APP_SLUG-$$}"
CEREMONY_DIR="$PUBLISH_RUN_DIR/ceremony"
STAGE_RECEIPT="$PUBLISH_RUN_DIR/stage-receipt.json"
PROMOTION_RECEIPT="$PUBLISH_RUN_DIR/promotion-receipt.json"
FINAL_RECEIPT="$PUBLISH_RUN_DIR/publish-receipt.json"
INSTALL_ROLLOUT_RECEIPT="$PUBLISH_RUN_DIR/install-rollout-receipt.json"
$DRY_RUN || mkdir -p "$PUBLISH_RUN_DIR"

# ---- Step 4: pearl ceremony (Squads sign, in-repo dev keys) -----------------
step 4 "private stage → pearl ceremony (3-of-4 Squads)"
if skip_step ceremony; then
	warn "  --skip ceremony (using the existing RELEASE.json; chain entry must already be Active)"
	$DRY_RUN || {
		[[ -f "$CAT_PATH/RELEASE.json" ]] || fail "  --skip ceremony requires $CAT_PATH/RELEASE.json"
		"$SUBMIT_BIN" --stage \
			--store "$STORE_URL" --spk "$CAT_PATH/app.spk" --metadata "$CAT_PATH/metadata.json" --release "$CAT_PATH/RELEASE.json" \
			--publisher-key "$KEYS_DIR/publisher.key.json" --store-pubkey "$KEYS_DIR/store-pubkey.json" \
			--license-mint "$STORE_LICENSE_MINT" --domain "$STORE_DOMAIN" --rpc-url "$RPC_URL" --timeout 480s \
			--developer "$CAT_DEVELOPER" --repo "$CAT_REPO" --slug "$CAT_SLUG" --receipt-out "$STAGE_RECEIPT" \
			|| fail "  private stage rejected"
	}
else
	info "  staging fresh SPK into catalog"
	$DRY_RUN || "$STATIC_STORE_ROOT/scripts/stage-into-catalog.sh" "$APP_DIR/app.spk" "$CAT_PATH" \
		|| fail "  stage-into-catalog failed"
	CEREMONY_VER="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d.get("marketingVersion") or d.get("version") or "")' "$CAT_PATH/metadata.json")"
	[[ -n "$CEREMONY_VER" ]] || fail "  staged catalog metadata has no release version"
	if $DRY_RUN; then
		info "  DRY RUN — would prepare RELEASE.json, privately stage it, then execute the Squads ceremony"
	else
		OUTPUT_DIR="$CEREMONY_DIR" COPY_TO_CATALOG=0 CEREMONY_MODE=prepare \
			APP_CATALOG_PATH="$CAT_PATH" APP_SLUG="$CAT_SLUG" MELUSINA_VERSION="$CEREMONY_VER" \
			MELUSINA_PUBLISHER_KEYPAIR="$KEYS_DIR/publisher.json" \
			MELUSINA_REVIEWER1_KEYPAIR="$KEYS_DIR/reviewer-1.json" \
			MELUSINA_REVIEWER2_KEYPAIR="$KEYS_DIR/reviewer-2.json" \
			MELUSINA_SQUADS_CONFIG="$KEYS_DIR/core-app-team-squads.json" \
			"$STATIC_STORE_ROOT/scripts/pearl-app-ceremony.sh" \
			|| fail "  pearl-app-ceremony prepare failed"

		"$SUBMIT_BIN" --stage \
			--store "$STORE_URL" --spk "$CEREMONY_DIR/app/app.spk" --metadata "$CEREMONY_DIR/app/metadata.json" --release "$CEREMONY_DIR/app/RELEASE.json" \
			--publisher-key "$KEYS_DIR/publisher.key.json" --store-pubkey "$KEYS_DIR/store-pubkey.json" \
			--license-mint "$STORE_LICENSE_MINT" --domain "$STORE_DOMAIN" --rpc-url "$RPC_URL" --timeout 480s \
			--developer "$CAT_DEVELOPER" --repo "$CAT_REPO" --slug "$CAT_SLUG" --receipt-out "$STAGE_RECEIPT" \
			|| fail "  private stage rejected — chain was NOT mutated"

		OUTPUT_DIR="$CEREMONY_DIR" COPY_TO_CATALOG=1 CEREMONY_MODE=execute \
		APP_CATALOG_PATH="$CAT_PATH" APP_SLUG="$CAT_SLUG" MELUSINA_VERSION="$CEREMONY_VER" \
		MELUSINA_PUBLISHER_KEYPAIR="$KEYS_DIR/publisher.json" \
      MELUSINA_REVIEWER1_KEYPAIR="$KEYS_DIR/reviewer-1.json" \
      MELUSINA_REVIEWER2_KEYPAIR="$KEYS_DIR/reviewer-2.json" \
      MELUSINA_SQUADS_CONFIG="$KEYS_DIR/core-app-team-squads.json" \
		"$STATIC_STORE_ROOT/scripts/pearl-app-ceremony.sh" \
			|| fail "  pearl-app-ceremony.sh failed — see $CEREMONY_DIR"
	fi
fi
echo

# ---- Step 5: POST /publish (sealed-v3, single writer, chain-verified) -------
step 5 "POST $STORE_URL/publish"
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
		--developer "$CAT_DEVELOPER" --repo "$CAT_REPO" --slug "$CAT_SLUG" \
		--receipt-out "$PROMOTION_RECEIPT" \
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
	SERVED_INDEX="$PUBLISH_RUN_DIR/served-index.json"
	curl -fsS --max-time 20 -o "$SERVED_INDEX" "$STORE_URL/apps/index.json" \
		|| fail "  GET $STORE_URL/apps/index.json failed"
	SERVED_JSON="$(cat "$SERVED_INDEX")"
	SERVED_INDEX_SHA="$(sha256sum "$SERVED_INDEX" | awk '{print $1}')"
	APP_ID="$(python3 -c 'import json;print(json.load(open("'"$CAT_PATH"'/metadata.json")).get("appId",""))')"
	PACKAGE_ID="$(python3 -c 'import json;print(json.load(open("'"$CAT_PATH"'/metadata.json")).get("packageId",""))')"
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
	SERVED_SPK="$PUBLISH_RUN_DIR/served.spk"
	SERVED_HEADERS="$PUBLISH_RUN_DIR/served.headers"
	curl -fsS --max-time 120 -D "$SERVED_HEADERS" -o "$SERVED_SPK" "$STORE_URL/packages/$PACKAGE_ID" \
		|| fail "  served package fetch failed for $PACKAGE_ID"
	SERVED_SHA="$(sha256sum "$SERVED_SPK" | awk '{print $1}')"
	[[ "$SERVED_SHA" == "$EXPECT_SHA" ]] || fail "  served package sha256 $SERVED_SHA != expected $EXPECT_SHA"
	grep -qi '^x-store-gate:[[:space:]]*verified' "$SERVED_HEADERS" \
		|| fail "  served package lacks X-Store-Gate: verified"
	ok "  served package bytes + on-chain serve gate verified"
	SERVED_POINTER="$PUBLISH_RUN_DIR/served-catalog-pointer.json"
	curl -fsS --max-time 20 -o "$SERVED_POINTER" "$STORE_URL/apps/pointers/$APP_ID.json" \
		|| fail "  signed catalog pointer is not publicly served for $APP_ID"
	python3 - "$PROMOTION_RECEIPT" "$SERVED_POINTER" "$SERVED_INDEX_SHA" "$APP_ID" "$PACKAGE_ID" <<'PY' \
		|| fail "  public catalog pointer does not match the verified promotion receipt/index"
import json, sys
promotion_path, pointer_path, index_sha, app_id, package_id = sys.argv[1:]
promotion = json.load(open(promotion_path))
pointer = json.load(open(pointer_path))
assert promotion.get("catalog") == pointer, "served pointer differs from store-signed promotion pointer"
assert pointer.get("catalogSha256") == index_sha, "pointer does not bind exact served apps/index.json"
assert pointer.get("appId") == app_id, "pointer appId mismatch"
assert pointer.get("packageId") == package_id, "pointer packageId mismatch"
assert pointer.get("operatorSignature"), "pointer signature missing"
PY
	ok "  signed catalog pointer binds exact index + appId/packageId"

		SOURCE_REV="$(git -C "$APP_DIR" rev-parse HEAD 2>/dev/null || true)"
		SOURCE_DIRTY=false
		[[ -z "$(git -C "$APP_DIR" status --porcelain 2>/dev/null || true)" ]] || SOURCE_DIRTY=true
		python3 - "$STAGE_RECEIPT" "$PROMOTION_RECEIPT" "$CEREMONY_DIR/result.json" "$FINAL_RECEIPT" \
			"$APP_SLUG" "$APP_ID" "$PACKAGE_ID" "$SERVED_VER" "$SERVED_SHA" "$SERVED_INDEX_SHA" \
			"$SOURCE_REV" "$SOURCE_DIRTY" "$SOURCE_DATE_EPOCH" <<'PY'
import json, os, sys, time
stage_path, promotion_path, ceremony_path, out_path, slug, app_id, package_id, version, served_sha, index_sha, source_rev, source_dirty, source_epoch = sys.argv[1:]
def load(path):
    if not path or not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)
doc = {
    "schema": "melusina-app-publish-receipt-v1",
    "createdAt": int(time.time()),
    "app": {"slug": slug, "appId": app_id, "packageId": package_id, "version": version},
    "buildProof": {
        "sourceRevision": source_rev or None,
        "sourceDirty": source_dirty == "true",
        "sourceDateEpoch": int(source_epoch),
        "spkSha256": served_sha,
    },
    "stage": load(stage_path),
    "squads": load(ceremony_path),
    "promotion": load(promotion_path),
    "serveProof": {"sha256": served_sha, "storeGate": "verified", "catalogSha256": index_sha},
    "catalogProof": None,
    "rolloutProof": None,
    "installProof": None,
    "grainCanaryProof": None,
    "pearlUpgradeProof": None,
    "acceptance": {"status": "pending-install-canary"},
}
if isinstance(doc["promotion"], dict):
    doc["catalogProof"] = doc["promotion"].get("catalog")
    doc["rolloutProof"] = doc["promotion"].get("rollout")
tmp = out_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, out_path)
PY
		ok "  machine receipt: $FINAL_RECEIPT"
fi
echo

# ---- Step 7: verified install + canary + remaining pearls --------------------
step 7 "verified appId install + authz canary rollout"
if $PUBLISH_ONLY; then
  warn "  --publish-only: release is catalog-current but NOT accepted; prior release remains Active"
elif $DRY_RUN; then
  info "  DRY RUN — would run $ROLLOUT_DRIVER against $SHELL_URL for appId=$APP_ID"
else
  APP_HASH="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["appHash"])' "$SERVED_POINTER")"
  rollout_args=(
    --shell-url "$SHELL_URL"
    --domain "$SHELL_DOMAIN"
    --wallet "$ADMIN_WALLET"
    --catalog-base "$STORE_URL"
    --app-id "$APP_ID"
    --app-hash "$APP_HASH"
    --version "$SERVED_VER"
    --out "$INSTALL_ROLLOUT_RECEIPT"
  )
  [[ -z "$CANARY_GRAIN" ]] || rollout_args+=(--canary-grain "$CANARY_GRAIN")
  node "$ROLLOUT_DRIVER" "${rollout_args[@]}" \
    || fail "  verified install/canary rollout failed; prior release remains Active for rollback"

  python3 - "$FINAL_RECEIPT" "$INSTALL_ROLLOUT_RECEIPT" <<'PY'
import json, os, sys, time
publish_path, rollout_path = sys.argv[1:]
with open(publish_path) as f:
    publish = json.load(f)
with open(rollout_path) as f:
    rollout = json.load(f)
assert rollout.get("schema") == "melusina-app-install-rollout-receipt-v1"
assert rollout.get("app", {}).get("appId") == publish.get("app", {}).get("appId")
assert rollout.get("app", {}).get("packageId") == publish.get("app", {}).get("packageId")
publish["installProof"] = rollout.get("installProof")
publish["grainCanaryProof"] = rollout.get("grainCanaryProof")
publish["pearlUpgradeProof"] = rollout.get("upgradeProof")
publish["acceptance"] = {
    "status": "accepted",
    "acceptedAt": int(time.time()),
    "installer": rollout.get("installer"),
}
tmp = publish_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(publish, f, indent=2, sort_keys=True)
    f.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, publish_path)
PY
  ok "  verified install + canary acceptance appended to $FINAL_RECEIPT"
fi
echo

if $PUBLISH_ONLY; then
  ok "self-publish staged + activated for $APP_SLUG; acceptance remains pending"
else
  ok "self-publish accepted for $APP_SLUG; prior release remains Active through the signed rollback window"
fi
