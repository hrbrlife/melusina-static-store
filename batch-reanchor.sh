#!/usr/bin/env bash
# Batch pearl-ceremony re-anchor: for every staging app whose
# apphash.Canonical(app.spk, metadata.json) != its RELEASE.json appHash (or has
# no RELEASE.json), run the proven pearl-app-ceremony.sh to mint a fresh on-chain
# ReleaseEntry for the CURRENT staged bytes. Sequential (Squads tx-index must not
# race). HT13: fleet keypairs via the ceremony's defaults; no hot keys.
set -uo pipefail
cd /home/user/Desktop/static_store
source .publish.env
LOG=/home/user/Desktop/agentchat/.spawns/wave-build/batch-reanchor.log
: > "$LOG"

mapfile -t TARGETS < <(python3 - <<'PY'
import hashlib,json,os,glob
def can(d):
    o=hashlib.sha256()
    for rel,p in sorted([("app.spk",f"{d}/app.spk"),("metadata.json",f"{d}/metadata.json")]):
        i=hashlib.sha256(); i.update(b"F "+rel.encode()+b"\x00"+open(p,"rb").read()); o.update(i.digest())
    return o.hexdigest()
for d in sorted(glob.glob("packages/hrbrlife/*/*")):
    if not (os.path.isfile(f"{d}/app.spk") and os.path.isfile(f"{d}/metadata.json")): continue
    m=json.load(open(f"{d}/metadata.json"))
    relp=f"{d}/RELEASE.json"
    claim=json.load(open(relp)).get("appHash","") if os.path.isfile(relp) else ""
    if can(d)!=claim:
        print(f"{os.path.basename(d)}\t{d}\t{m.get('version','0.0.0')}")
PY
)

echo "BATCH: ${#TARGETS[@]} apps to re-anchor" | tee -a "$LOG"
PASS=0; FAIL=0; FAILED_APPS=()
for line in "${TARGETS[@]}"; do
  slug="$(cut -f1 <<<"$line")"; dir="$(cut -f2 <<<"$line")"; ver="$(cut -f3 <<<"$line")"
  echo "==== [$((PASS+FAIL+1))/${#TARGETS[@]}] ceremony: $slug v$ver ($dir) ====" | tee -a "$LOG"
  if APP_CATALOG_PATH="$PWD/$dir" APP_SLUG="$slug" MELUSINA_VERSION="$ver" \
       timeout 600 bash scripts/pearl-app-ceremony.sh >>"$LOG" 2>&1; then
    # confirm the written RELEASE.json now matches the staged apphash
    match=$(python3 - "$dir" <<'PY'
import hashlib,json,sys
d=sys.argv[1]
o=hashlib.sha256()
for rel,p in sorted([("app.spk",f"{d}/app.spk"),("metadata.json",f"{d}/metadata.json")]):
    i=hashlib.sha256(); i.update(b"F "+rel.encode()+b"\x00"+open(p,"rb").read()); o.update(i.digest())
claim=json.load(open(f"{d}/RELEASE.json")).get("appHash","")
print("YES" if o.hexdigest()==claim else "NO")
PY
)
    if [ "$match" = YES ]; then echo "  -> OK anchored+verified $slug" | tee -a "$LOG"; ((PASS++)); else echo "  -> FAIL post-verify mismatch $slug" | tee -a "$LOG"; ((FAIL++)); FAILED_APPS+=("$slug"); fi
  else
    echo "  -> FAIL ceremony exit nonzero $slug" | tee -a "$LOG"; ((FAIL++)); FAILED_APPS+=("$slug")
  fi
done
echo "BATCH DONE: PASS=$PASS FAIL=$FAIL" | tee -a "$LOG"
[ "$FAIL" -gt 0 ] && echo "FAILED: ${FAILED_APPS[*]}" | tee -a "$LOG"
echo "BATCH_REANCHOR_EXIT=$FAIL"
