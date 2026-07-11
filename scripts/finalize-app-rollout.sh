#!/usr/bin/env bash
#
# Retire the immediately previous app release only after a successful install
# canary, remaining-grain acceptance, and the store-signed rollback deadline.
# This is deliberately separate from self-publish.sh: the rollback window must
# remain usable, and no publish failure may strand the old release as Revoked.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RECEIPT=""
KEYS_DIR=""
WAIT=false
STORE_URL="${MELUSINA_STORE_URL:-https://bazaar.melusina-os.org}"
RPC_URL="${MELUSINA_STORE_RPC_URL:-${MELUSINA_RPC_URL:-}}"
STORE_DOMAIN="${MELUSINA_STORE_DOMAIN:-bazaar.melusina-os.org}"
STORE_LICENSE_MINT="${MELUSINA_STORE_LICENSE_MINT:-35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN}"
MASTER_NFT_ATA="${MELUSINA_MASTER_NFT_ATA:-EA2FEHzhg4ZunhchFhcBMjaVtTh3pGkEy2SG6FEmYepn}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --receipt) RECEIPT="$2"; shift 2 ;;
    --keys) KEYS_DIR="$2"; shift 2 ;;
    --store) STORE_URL="$2"; shift 2 ;;
    --wait) WAIT=true; shift ;;
    -h|--help)
      echo "usage: $0 --receipt publish-receipt.json --keys dev-publish-keys [--wait]"
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -f "$RECEIPT" ]] || { echo "receipt not found: $RECEIPT" >&2; exit 2; }
[[ -d "$KEYS_DIR" ]] || { echo "keys directory not found: $KEYS_DIR" >&2; exit 2; }
[[ -n "$RPC_URL" ]] || { echo "MELUSINA_STORE_RPC_URL or MELUSINA_RPC_URL is required" >&2; exit 2; }
for file in publisher.json reviewer-1.json reviewer-2.json core-app-team-squads.json; do
  [[ -f "$KEYS_DIR/$file" ]] || { echo "missing $KEYS_DIR/$file" >&2; exit 2; }
done

SUBMIT_BIN="$ROOT/sidecar/melusina-store-sidecar/bin/submit"
if [[ ! -x "$SUBMIT_BIN" ]]; then
  (cd "$ROOT/sidecar/melusina-store-sidecar" && mkdir -p bin && \
    go build -o bin/submit ./cmd/submit)
fi
"$SUBMIT_BIN" \
  --verify-receipt "$RECEIPT" \
  --license-mint "$STORE_LICENSE_MINT" \
  --domain "$STORE_DOMAIN" \
  --rpc-url "$RPC_URL"

readarray -t facts < <(python3 - "$RECEIPT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("schema") == "melusina-app-publish-receipt-v1", "wrong receipt schema"
assert d.get("acceptance", {}).get("status") == "accepted", "rollout is not accepted"
r = d.get("rolloutProof") or {}
c = d.get("catalogProof") or {}
assert r.get("operatorSignature"), "signed store rollout proof missing"
assert c.get("operatorSignature"), "signed catalog pointer missing"
assert r.get("appId") == d.get("app", {}).get("appId"), "rollout appId mismatch"
assert c.get("appId") == r.get("appId"), "catalog appId mismatch"
assert c.get("appHash") == r.get("currentAppHash"), "current app hash mismatch"
assert c.get("previousAppHash", "") == r.get("previousAppHash", ""), "previous app hash mismatch"
print(d.get("app", {}).get("slug", "app"))
print(r.get("appId", ""))
print(r.get("currentAppHash", ""))
print(r.get("previousAppHash", ""))
print(r.get("previousValidUntil", 0))
print((d.get("squads") or {}).get("releaseEntryPda", ""))
PY
)
APP_SLUG="${facts[0]}"
APP_ID="${facts[1]}"
CURRENT_HASH="${facts[2]}"
PREVIOUS_HASH="${facts[3]}"
VALID_UNTIL="${facts[4]}"
CURRENT_PDA="${facts[5]}"

if [[ -z "$PREVIOUS_HASH" ]]; then
  echo "No previous release is attached to this rollout; nothing to retire."
  exit 0
fi
[[ -n "$CURRENT_PDA" ]] || { echo "current Squads releaseEntryPda missing from receipt" >&2; exit 1; }

now="$(date +%s)"
if (( now < VALID_UNTIL )); then
  if ! $WAIT; then
    echo "rollback window remains open until $VALID_UNTIL ($((VALID_UNTIL - now))s); refusing early revocation" >&2
    exit 1
  fi
  sleep "$((VALID_UNTIL - now))"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsS --max-time 30 "$STORE_URL/apps/pointers/$APP_ID.json" > "$tmp/pointer.json"
python3 - "$RECEIPT" "$tmp/pointer.json" "$CURRENT_HASH" "$PREVIOUS_HASH" "$VALID_UNTIL" <<'PY'
import json, sys
receipt = json.load(open(sys.argv[1]))
p = json.load(open(sys.argv[2]))
signed = (receipt.get("promotion") or {}).get("catalog")
assert isinstance(signed, dict), "verified receipt has no signed catalog pointer"
assert p == signed, "live catalog pointer differs from verified signed promotion pointer"
assert p.get("appHash") == sys.argv[3], "live pointer current hash drift"
assert p.get("previousAppHash") == sys.argv[4], "live pointer previous hash drift"
assert int(p.get("previousValidUntil", 0)) == int(sys.argv[5]), "live rollback deadline drift"
PY

LIST_BIN="$ROOT/sidecar/melusina-store-sidecar/bin/list-active-releases"
if [[ ! -x "$LIST_BIN" ]]; then
  (cd "$ROOT/sidecar/melusina-store-sidecar" && mkdir -p bin && \
    go build -o bin/list-active-releases ./cmd/list-active-releases)
fi
"$LIST_BIN" -rpc-url "$RPC_URL" -known-pda "$CURRENT_PDA" > "$tmp/active-before.jsonl"
PREVIOUS_PDA="$(python3 - "$tmp/active-before.jsonl" "$CURRENT_HASH" "$PREVIOUS_HASH" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
current = [r for r in rows if r.get("appHash") == sys.argv[2]]
previous = [r for r in rows if r.get("appHash") == sys.argv[3]]
assert len(current) == 1, f"expected one Active current release, found {len(current)}"
assert len(previous) == 1, f"expected one Active previous release, found {len(previous)}"
print(previous[0]["pda"])
PY
)"

REVOKE_DIR="$tmp/revoke"
OUTPUT_DIR="$REVOKE_DIR" \
STALE_RELEASE_ENTRY_PDA="$PREVIOUS_PDA" \
MASTER_NFT_ATA="$MASTER_NFT_ATA" \
MELUSINA_RPC_URL="$RPC_URL" \
MELUSINA_SQUADS_CONFIG="$KEYS_DIR/core-app-team-squads.json" \
MELUSINA_PUBLISHER_KEYPAIR="$KEYS_DIR/publisher.json" \
MELUSINA_REVIEWER1_KEYPAIR="$KEYS_DIR/reviewer-1.json" \
MELUSINA_REVIEWER2_KEYPAIR="$KEYS_DIR/reviewer-2.json" \
  "$SCRIPT_DIR/revoke-release-ceremony.sh" "$APP_SLUG"

"$LIST_BIN" -rpc-url "$RPC_URL" -known-pda "$CURRENT_PDA" > "$tmp/active-after.jsonl"
python3 - "$RECEIPT" "$REVOKE_DIR/result.json" "$tmp/active-after.jsonl" \
  "$CURRENT_HASH" "$PREVIOUS_HASH" "$PREVIOUS_PDA" <<'PY'
import json, os, sys, time
receipt_path, revoke_path, active_path, current_hash, previous_hash, previous_pda = sys.argv[1:]
with open(receipt_path) as f:
    receipt = json.load(f)
with open(revoke_path) as f:
    revoke = json.load(f)
rows = [json.loads(line) for line in open(active_path) if line.strip()]
assert len([r for r in rows if r.get("appHash") == current_hash]) == 1, "current release lost"
assert not [r for r in rows if r.get("appHash") == previous_hash], "previous release still Active"
receipt["retirementProof"] = {
    "status": "previous-revoked-after-acceptance-window",
    "retiredAt": int(time.time()),
    "previousAppHash": previous_hash,
    "previousReleaseEntryPda": previous_pda,
    "squads": revoke,
    "currentReleaseStillActive": True,
}
tmp = receipt_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(receipt, f, indent=2, sort_keys=True)
    f.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, receipt_path)
PY

echo "Previous release $PREVIOUS_PDA revoked after accepted rollback window."
echo "Receipt updated: $RECEIPT"
