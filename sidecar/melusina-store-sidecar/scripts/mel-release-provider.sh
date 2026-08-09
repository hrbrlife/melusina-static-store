#!/usr/bin/env bash
#
# mel-release-provider.sh -- governed local release-runner for `mel-release`.
#
# This is intentionally a provider, not a second publisher.  It runs only on
# the release workstation that holds the approval identities; targets and the
# store never receive a Squads member or author private key.  The caller is the
# Go `mel-release` CLI, which binds every resulting receipt into its durable
# WAL.  The two authority boundaries are literal commands:
#
#   mel-release publish -> build, private stage, UNEXECUTED Squads proposal
#   mel-release approve -> member approvals, execute, promote, generation
#
# The register-release execution requires the Ed25519 precompile as the outer
# instruction immediately before the Squads execute instruction.  The companion
# .mjs helper deliberately constructs that transaction; generic
# squads-vault-exec.js cannot do so and produces the misleading "Failed to
# unpack instruction data" failure for ReleaseEntry registration.

set -euo pipefail
umask 077

readonly PROVIDER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly NODE_HELPER="$PROVIDER_ROOT/scripts/mel-release-squads-register.mjs"
readonly APPHASH_CMD="$PROVIDER_ROOT/cmd/apphash"
readonly ACTIVE_CMD="$PROVIDER_ROOT/cmd/list-active-releases"
readonly RUNTIME_CONTRACT_SCHEMA="melusina-app-runtime-contract-v1"
readonly RUNTIME_CONTRACT_SCHEMA_URL="https://bazaar.melusina-os.org/schemas/melusina-app-runtime-contract-v1.schema.json"

die() { echo "mel-release-provider: $*" >&2; exit 2; }
need() {
  local n="$1" v
  v="$(printenv "$n" 2>/dev/null || true)"
  [[ -n "$v" ]] || die "missing required environment $n"
}
need_file() { local n="$1" p; need "$n"; p="$(printenv "$n")"; [[ -f "$p" && ! -L "$p" ]] || die "$n must name a regular non-symlink file"; }
need_dir() { local n="$1" p; need "$n"; p="$(printenv "$n")"; [[ -d "$p" && ! -L "$p" ]] || die "$n must name a real non-symlink directory"; }
need_executable() { local n="$1" p; need_file "$n"; p="$(printenv "$n")"; [[ -x "$p" ]] || die "$n must name an executable file"; }
json_get() { python3 - "$1" "$2" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
cur = data
for key in sys.argv[2].split('.'):
    cur = cur[key]
if isinstance(cur, (dict, list)):
    print(json.dumps(cur, separators=(",", ":")))
else:
    print(cur)
PY
}
write_json() { # path then JSON supplied on stdin; private, atomic, no symlink replacement
  local out="$1" tmp
  [[ "$out" = /* && "$out" != *"/../"* ]] || die "receipt path must be absolute and clean: $out"
  mkdir -p "$(dirname "$out")"
  tmp="$(mktemp "$(dirname "$out")/.tmp.XXXXXX")"
  cat >"$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$out"
}
copy_private() {
  local source="$1" dest="$2"
  [[ -f "$source" && ! -L "$source" ]] || die "source must be a regular non-symlink file: $source"
  install -m 600 "$source" "$dest"
}
run_go_cmd() { # a source command in this exact sidecar module, never an unknown PATH binary
  local cmd="$1"; shift
  (cd "$PROVIDER_ROOT" && go run "$cmd" "$@")
}
submit_cmd() {
  if [[ -n "${MEL_RELEASE_SUBMIT_BIN:-}" ]]; then
    [[ -x "$MEL_RELEASE_SUBMIT_BIN" && ! -L "$MEL_RELEASE_SUBMIT_BIN" ]] || die "MEL_RELEASE_SUBMIT_BIN must be an executable non-symlink file"
    "$MEL_RELEASE_SUBMIT_BIN" "$@"
  else
    run_go_cmd "$PROVIDER_ROOT/cmd/submit" "$@"
  fi
}

# Validate the exact private runtime declaration before it enters the release
# ceremony. The submit client and sidecar repeat this check with the canonical Go
# validator at stage/promote time; this provider-side check makes `build` fail at
# the candidate boundary instead of producing a receipt for unusable material.
validate_runtime_contract_exact() {
  local contract="$1" spk="$2" metadata="$3" app_id="$4" version="$5" app_hash="$6"
  [[ -f "$contract" && ! -L "$contract" ]] || die "runtime contract must be a regular non-symlink file: $contract"
  [[ -f "$spk" && ! -L "$spk" ]] || die "runtime-contract SPK must be a regular non-symlink file: $spk"
  [[ -f "$metadata" && ! -L "$metadata" ]] || die "runtime-contract metadata must be a regular non-symlink file: $metadata"
  python3 - "$contract" "$spk" "$metadata" "$app_id" "$version" "$app_hash" "$RUNTIME_CONTRACT_SCHEMA" "$RUNTIME_CONTRACT_SCHEMA_URL" <<'PY'
import hashlib, json, re, sys

contract_path, spk_path, metadata_path, app_id, version, app_hash, schema, schema_url = sys.argv[1:]

def reject_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out

def exact_keys(value, keys, where):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{where} must contain exactly {sorted(keys)}")

def text(value):
    return isinstance(value, str) and len(value.strip()) >= 3

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

with open(contract_path, "rb") as fh:
    raw = fh.read()
if not raw:
    raise SystemExit("runtime contract is empty")
try:
    contract = json.loads(raw, object_pairs_hook=reject_duplicates)
except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
    raise SystemExit(f"decode runtime contract: {exc}")

try:
    exact_keys(contract, ("$schema", "schema", "app", "sidecars", "launchProbe", "fixtures", "cleanup"), "runtime contract")
    if contract["$schema"] != schema_url or contract["schema"] != schema:
        raise ValueError("runtime contract schema does not match the supported v1 schema")

    app = contract["app"]
    exact_keys(app, ("appId", "version", "spkSha256", "appHash"), "app")
    metadata = json.load(open(metadata_path, encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(metadata, dict) or metadata.get("appId", "").strip() != app_id:
        raise ValueError("metadata appId does not match the governed appId")
    spk_sha = sha256_file(spk_path)
    expected_app = {"appId": app_id, "version": version, "spkSha256": spk_sha, "appHash": app_hash}
    if app != expected_app:
        raise ValueError(f"runtime contract app binding differs from {expected_app}")
    if not re.fullmatch(r"[0-9a-f]{64}", app_hash):
        raise ValueError("governed appHash is not lowercase SHA-256 hex")

    sidecar_id = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
    host = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.sidecar\.(?:host|hypervisor(?:\.shared)?|local|remote(?:\.shared)?)\Z")
    sidecars = contract["sidecars"]
    if not isinstance(sidecars, list):
        raise ValueError("sidecars must be an array (use [] when none are required)")
    seen_ids, seen_hosts = set(), set()
    for index, sidecar in enumerate(sidecars):
        where = f"sidecars[{index}]"
        exact_keys(sidecar, ("id", "host", "port", "transport", "tls", "capabilities", "safeProbe"), where)
        if not isinstance(sidecar["id"], str) or not sidecar_id.fullmatch(sidecar["id"]) or sidecar["id"] in seen_ids:
            raise ValueError(f"{where}.id is invalid or duplicated")
        if not isinstance(sidecar["host"], str) or not host.fullmatch(sidecar["host"]) or sidecar["host"] in seen_hosts:
            raise ValueError(f"{where}.host is invalid or duplicated")
        seen_ids.add(sidecar["id"]); seen_hosts.add(sidecar["host"])
        port = sidecar["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 or sidecar["transport"] != "https":
            raise ValueError(f"{where} requires an explicit HTTPS TCP port")
        tls = sidecar["tls"]
        exact_keys(tls, ("required", "serverName", "trust", "minimumVersion"), where + ".tls")
        if tls != {"required": True, "serverName": sidecar["host"], "trust": "system-ca", "minimumVersion": tls.get("minimumVersion")} or tls["minimumVersion"] not in ("TLS1.2", "TLS1.3"):
            raise ValueError(f"{where}.tls must require system-ca TLS for the exact host")
        capabilities = sidecar["capabilities"]
        if not isinstance(capabilities, list) or "http-out" not in capabilities or len(capabilities) != len(set(capabilities)) or any(not isinstance(item, str) or not sidecar_id.fullmatch(item) for item in capabilities):
            raise ValueError(f"{where}.capabilities is invalid")
        probe = sidecar["safeProbe"]
        exact_keys(probe, ("action", "expectedResult"), where + ".safeProbe")
        if not text(probe["action"]) or not text(probe["expectedResult"]):
            raise ValueError(f"{where}.safeProbe is incomplete")

    launch = contract["launchProbe"]
    exact_keys(launch, ("kind", "steps", "expectedResult"), "launchProbe")
    if launch["kind"] != "visible-ui" or not isinstance(launch["steps"], list) or not launch["steps"] or not text(launch["expectedResult"]):
        raise ValueError("launchProbe must declare a visible UI result and at least one step")
    for index, step in enumerate(launch["steps"]):
        exact_keys(step, ("action", "expectedResult"), f"launchProbe.steps[{index}]")
        if not text(step["action"]) or not text(step["expectedResult"]):
            raise ValueError(f"launchProbe.steps[{index}] is incomplete")

    fixtures = contract["fixtures"]
    if not isinstance(fixtures, list):
        raise ValueError("fixtures must be an array (use [] when none are required)")
    for index, fixture in enumerate(fixtures):
        exact_keys(fixture, ("name", "purpose", "setup"), f"fixtures[{index}]")
        if not all(text(fixture[field]) for field in ("name", "purpose", "setup")):
            raise ValueError(f"fixtures[{index}] is incomplete")

    cleanup = contract["cleanup"]
    exact_keys(cleanup, ("steps",), "cleanup")
    if not isinstance(cleanup["steps"], list) or not cleanup["steps"] or any(not text(step) for step in cleanup["steps"]):
        raise ValueError("cleanup.steps must explicitly describe cleanup")
except (KeyError, TypeError, ValueError) as exc:
    raise SystemExit(f"invalid runtime contract: {exc}")
PY
}

pin_runtime_contract() {
  local state="$1" contract="$2" digest tmp
  digest="$(sha256sum "$contract" | awk '{print $1}')"
  tmp="$(mktemp "$state/.runtime-contract.sha256.XXXXXX")"
  printf '%s\n' "$digest" >"$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$state/runtime-contract.sha256"
}

assert_runtime_contract_frozen() {
  local state="$1" app_id="$2" version="$3" app_hash="$4" contract expected actual
  contract="$state/material/RUNTIME-CONTRACT.json"
  [[ -f "$state/runtime-contract.sha256" && ! -L "$state/runtime-contract.sha256" ]] || die "built runtime-contract digest is missing; run publish/build first"
  expected="$(tr -d '[:space:]' <"$state/runtime-contract.sha256")"
  actual="$(sha256sum "$contract" | awk '{print $1}')"
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" = "$expected" ]] || die "private runtime contract drifted after build"
  [[ -f "$state/pearl-material/app.spk" && ! -L "$state/pearl-material/app.spk" && -f "$state/pearl-material/metadata.json" && ! -L "$state/pearl-material/metadata.json" ]] || die "private Pearl ceremony material is missing"
  cmp -s "$state/material/app.spk" "$state/pearl-material/app.spk" || die "Pearl ceremony SPK drifted from private publication material"
  cmp -s "$state/material/metadata.json" "$state/pearl-material/metadata.json" || die "Pearl ceremony metadata drifted from private publication material"
  validate_runtime_contract_exact "$contract" "$state/material/app.spk" "$state/material/metadata.json" "$app_id" "$version" "$app_hash"
}

# A catalog slot is needed only when an app is not yet present in the store.
# Accept an absent triple for existing entries, but never accept a partial path:
# that would let staging and promotion disagree about the visible package slot.
catalog_slot_args() {
  local developer="${MEL_RELEASE_CATALOG_DEVELOPER:-}"
  local repo="${MEL_RELEASE_CATALOG_REPO:-}"
  local slug="${MEL_RELEASE_CATALOG_SLUG:-}"
  SUBMIT_CATALOG_SLOT_ARGS=()
  if [[ -z "$developer" && -z "$repo" && -z "$slug" ]]; then
    return
  fi
  [[ -n "$developer" && -n "$repo" && -n "$slug" ]] || die "catalog slot requires MEL_RELEASE_CATALOG_DEVELOPER, MEL_RELEASE_CATALOG_REPO, and MEL_RELEASE_CATALOG_SLUG together"
  SUBMIT_CATALOG_SLOT_ARGS=(--developer "$developer" --repo "$repo" --slug "$slug")
}

readonly OP="${1:-}"
[[ $# -eq 1 ]] || die "usage: $0 {build|active-releases|release-status|served-app-hash|stage|propose-register|approve-register|promote|revoke}"
case "$OP" in
  build|active-releases|release-status|served-app-hash|stage|propose-register|approve-register|promote|revoke) ;;
  *) die "unknown operation: $OP" ;;
esac

need MEL_RELEASE_STATE_DIR
[[ "$MEL_RELEASE_STATE_DIR" = /* && "$MEL_RELEASE_STATE_DIR" != *"/../"* ]] || die "MEL_RELEASE_STATE_DIR must be absolute and clean"
mkdir -p "$MEL_RELEASE_STATE_DIR/apps" "$MEL_RELEASE_STATE_DIR/locks"
chmod 700 "$MEL_RELEASE_STATE_DIR" "$MEL_RELEASE_STATE_DIR/apps" "$MEL_RELEASE_STATE_DIR/locks" 2>/dev/null || true

app_dir_for() {
  need MEL_APP_ID
  [[ "$MEL_APP_ID" =~ ^[a-z0-9]{52}$ ]] || die "MEL_APP_ID must be the immutable 52-character lower-case appId"
  printf '%s/apps/%s/provider' "$MEL_RELEASE_STATE_DIR" "$MEL_APP_ID"
}

build() {
  need MEL_APP_ID; need MEL_NEW_VERSION; need MEL_CANDIDATE_RECEIPT_OUT
  need_dir MEL_RELEASE_APP_DIR
  need MEL_RELEASE_MASTER_NFT_MINT
  local state app spk meta contract apphash artifact_sha artifact_size package_id metadata_appid metadata_version runtime_sha runtime_size
  state="$(app_dir_for)"; app="$(realpath -e "$MEL_RELEASE_APP_DIR")"
  spk="${MEL_RELEASE_SPK:-$app/app.spk}"; meta="${MEL_RELEASE_METADATA:-$app/metadata.json}"
  contract="${MEL_RELEASE_RUNTIME_CONTRACT:-$app/RUNTIME-CONTRACT.json}"
  [[ "$spk" = /* ]] || spk="$app/$spk"
  [[ "$meta" = /* ]] || meta="$app/$meta"
  [[ "$contract" = /* ]] || contract="$app/$contract"

  # The app's canonical Makefile owns build + deterministic package creation.
  # A ReleaseEntry cannot exist before the candidate SPK exists.  The source
  # Makefile still declares APP_PEARL_ENABLED=yes, but this one explicit
  # pre-approval mode performs only SPK parsing here.  approve-register later
  # finalizes and verifies this exact stored SPK against the on-chain entry
  # before the catalog pointer is promoted.
  (cd "$app" && MEL_RELEASE_PREAPPROVAL=1 "${MEL_RELEASE_MAKE:-make}" pack)
  [[ -f "$spk" && ! -L "$spk" ]] || die "pack did not produce a regular SPK: $spk"
  [[ -f "$meta" && ! -L "$meta" ]] || die "pack did not leave regular metadata: $meta"
  [[ -f "$contract" && ! -L "$contract" ]] || die "app must provide a regular non-symlink RUNTIME-CONTRACT.json: $contract"
  command -v spk >/dev/null || die "spk is required for release verification"
  spk verify "$spk" >/dev/null

  metadata_appid="$(python3 - "$meta" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("appId", ""))
PY
)"
  metadata_version="$(python3 - "$meta" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("version", ""))
PY
)"
  [[ "$metadata_appid" = "$MEL_APP_ID" ]] || die "metadata appId does not match MEL_APP_ID"
  [[ "$metadata_version" = "$MEL_NEW_VERSION" ]] || die "metadata version $metadata_version does not match MEL_NEW_VERSION $MEL_NEW_VERSION"

  mkdir -p "$state/material" "$state/pearl-material"
  copy_private "$spk" "$state/material/app.spk"
  copy_private "$meta" "$state/material/metadata.json"
  copy_private "$contract" "$state/material/RUNTIME-CONTRACT.json"
  # Pearl historically hashes every member of --app-dir. Keep its ceremony
  # view to canonical {app.spk, metadata.json}; the publication material also
  # carries the separately release-bound runtime contract.
  copy_private "$spk" "$state/pearl-material/app.spk"
  copy_private "$meta" "$state/pearl-material/metadata.json"
  apphash="$(run_go_cmd "$APPHASH_CMD" -spk "$state/material/app.spk" -metadata "$state/material/metadata.json")"
  [[ "$apphash" =~ ^[0-9a-f]{64}$ ]] || die "apphash command returned malformed hash"
  artifact_sha="$(sha256sum "$state/material/app.spk" | awk '{print $1}')"
  artifact_size="$(stat -c '%s' "$state/material/app.spk")"
  package_id="$(python3 - "$state/material/metadata.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("packageId", ""))
PY
  )"
  [[ "$package_id" = "${artifact_sha:0:32}" ]] || die "metadata packageId does not bind app.spk SHA-256"
  validate_runtime_contract_exact "$state/material/RUNTIME-CONTRACT.json" "$state/material/app.spk" "$state/material/metadata.json" "$MEL_APP_ID" "$MEL_NEW_VERSION" "$apphash"
  pin_runtime_contract "$state" "$state/material/RUNTIME-CONTRACT.json"
  runtime_sha="$(sha256sum "$state/material/RUNTIME-CONTRACT.json" | awk '{print $1}')"
  runtime_size="$(stat -c '%s' "$state/material/RUNTIME-CONTRACT.json")"

  python3 - "$MEL_CANDIDATE_RECEIPT_OUT" "$MEL_APP_ID" "$MEL_NEW_VERSION" "$artifact_sha" "$artifact_size" "$apphash" "$package_id" "$MEL_RELEASE_MASTER_NFT_MINT" "$state/material/app.spk" "$state/material/metadata.json" "$state/material/RUNTIME-CONTRACT.json" "$runtime_sha" "$runtime_size" "$RUNTIME_CONTRACT_SCHEMA" <<'PY'
import json, os, sys
out, app, version, sha, size, apphash, package, master, spk, meta, runtime_path, runtime_sha, runtime_size, runtime_schema = sys.argv[1:]
doc = {"schema":"melusina-app-candidate-receipt-v1", "app":{"appId":app,"version":version},
       "artifact":{"sha256":sha,"size":int(size)}, "appHash":apphash, "packageId":package,
       "masterNftMint":master,"spkPath":spk,"metadataPath":meta,
       "runtimeContract":{"path":runtime_path,"sha256":runtime_sha,"size":int(runtime_size),"schema":runtime_schema}}
tmp = out + ".tmp"
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(tmp, "w", encoding="utf-8") as f: json.dump(doc, f, sort_keys=True); f.write("\n")
os.chmod(tmp, 0o600); os.replace(tmp, out)
PY
}

active_releases() {
  need MEL_APP_ID; need MEL_RELEASE_RPC_URL; need MEL_PROGRAM_ID
  run_go_cmd "$ACTIVE_CMD" -rpc-url "$MEL_RELEASE_RPC_URL" -app-id "$MEL_APP_ID" -program-id "$MEL_PROGRAM_ID"
}

release_status() {
  # Decode only the stable ReleaseEntry fields needed by the release WAL.  This
  # is deliberately an exact-PDA read: cleanup must never infer a target from
  # a version string or from a mutable catalog pointer.
  need MEL_PDA; need MEL_RELEASE_RPC_URL; need MEL_PROGRAM_ID
  python3 - "$MEL_RELEASE_RPC_URL" "$MEL_PROGRAM_ID" "$MEL_PDA" <<'PY'
import base64, json, sys, urllib.request

rpc, program, pda = sys.argv[1:]
body = json.dumps({"jsonrpc":"2.0","id":1,"method":"getAccountInfo",
                   "params":[pda,{"encoding":"base64","commitment":"confirmed"}]}).encode()
req = urllib.request.Request(rpc, data=body, headers={"content-type":"application/json"})
with urllib.request.urlopen(req, timeout=30) as response:
    doc = json.load(response)
if doc.get("error"):
    raise SystemExit("ReleaseEntry RPC error: " + str(doc["error"]))
value = ((doc.get("result") or {}).get("value"))
if not isinstance(value, dict):
    raise SystemExit("ReleaseEntry is not present")
if value.get("owner") != program:
    raise SystemExit("ReleaseEntry owner does not match MEL_PROGRAM_ID")
try:
    raw = base64.b64decode(value["data"][0], validate=True)
except Exception as exc:
    raise SystemExit("ReleaseEntry base64 decode failed: " + str(exc))
# Anchor discriminator + master/appHash/appId/releaseHash + Borsh String(version)
offset = 8 + 32 + 32 + 32 + 32
if len(raw) < offset + 4:
    raise SystemExit("ReleaseEntry is truncated before version")
n = int.from_bytes(raw[offset:offset + 4], "little")
offset += 4
if n < 1 or len(raw) < offset + n + 32 + 32 + 64 + 32 + 32 + 8 + 1:
    raise SystemExit("ReleaseEntry has an invalid version/status layout")
try:
    version = raw[offset:offset+n].decode("utf-8")
except UnicodeDecodeError as exc:
    raise SystemExit("ReleaseEntry version is not UTF-8: " + str(exc))
offset += n + 32 + 32 + 64 + 32 + 32 + 8
status = raw[offset]
# AttestationStatus is Anchor/Borsh ordinal: Active=0, Revoked=1,
# Superseded=2.  Do not mistake an active ReleaseEntry for an invalid record.
if status not in (0, 1, 2):
    raise SystemExit("ReleaseEntry has unknown status " + str(status))
print(json.dumps({"pda":pda,"appHash":raw[8+32:8+64].hex(),"version":version,
                  "status":("Active", "Revoked", "Superseded")[status]}, separators=(",", ":")))
PY
}

revoke() {
  # This is intentionally a separate governed ceremony per exact stale PDA.
  # It runs only after mel-release has proved the new release is both Active
  # and served; no catalog or release identity is inferred here.
  need MEL_PDA; need MEL_REVOKE_RECEIPT_OUT; need MEL_PROGRAM_ID
  # A stale-PDA revoke is intentionally app-selector-free.  It needs the
  # master-holder vault and quorum, but not the source tree, appId, or author
  # signing key used to create the new ReleaseEntry proposal.
  need MEL_RELEASE_MASTER_NFT_MINT; need MEL_RELEASE_SQUADS_MULTISIG; need MEL_RELEASE_SQUADS_VAULT
  need MEL_RELEASE_SQUADS_THRESHOLD; need MEL_RELEASE_SQUADS_PROGRAM_ID; need MEL_RELEASE_RPC_URL
  [[ "$MEL_RELEASE_SQUADS_THRESHOLD" =~ ^[1-9][0-9]*$ ]] || die "MEL_RELEASE_SQUADS_THRESHOLD must be positive integer"
  local before master_ata executor ix result sig i
  local -a member_args=()
  before="$(release_status)"
  if [[ "$(python3 - "$before" <<'PY'
import json, sys
print(json.loads(sys.argv[1])["status"])
PY
)" = "Revoked" ]]; then
    python3 - "$MEL_REVOKE_RECEIPT_OUT" "$MEL_PDA" <<'PY'
import json, os, sys
out, pda = sys.argv[1:]
tmp = out + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump({"schema":"melusina-revoke-release-receipt-v1","releaseEntryPda":pda,
               "status":"Revoked","alreadyRevoked":True}, f, sort_keys=True); f.write("\n")
os.chmod(tmp, 0o600); os.replace(tmp, out)
PY
    return
  fi
  command -v spl-token >/dev/null 2>&1 || die "spl-token is required to derive master NFT custody ATA"
  master_ata="$(spl-token address --owner "$MEL_RELEASE_SQUADS_VAULT" --token "$MEL_RELEASE_MASTER_NFT_MINT" --verbose | awk -F': ' '/^Associated token address:/{print $2}')"
  [[ "$master_ata" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ ]] || die "ceremony masterNftAta is malformed"
  executor="${MEL_RELEASE_SQUADS_EXECUTOR:-/home/user/Desktop/Melusina/deployer/scripts/squads-vault-exec.js}"
  [[ -f "$executor" && ! -L "$executor" ]] || die "MEL_RELEASE_SQUADS_EXECUTOR must be a regular file"
  ix="$(mktemp "${TMPDIR:-/tmp}/mel-release-revoke.XXXXXXXX.ix.json")"
  chmod 600 "$ix"
  python3 - "$ix" "$MEL_PROGRAM_ID" "$MEL_PDA" "$MEL_RELEASE_SQUADS_VAULT" "$MEL_RELEASE_MASTER_NFT_MINT" "$master_ata" <<'PY'
import base64, hashlib, json, os, sys
out, program, release, vault, master, ata = sys.argv[1:]
doc = {
  "programId": program,
  "accounts": [
    {"pubkey": release, "isSigner": False, "isWritable": True},
    {"pubkey": vault, "isSigner": True, "isWritable": True},
    {"pubkey": master, "isSigner": False, "isWritable": False},
    {"pubkey": ata, "isSigner": False, "isWritable": False},
    {"pubkey": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "isSigner": False, "isWritable": False},
  ],
  "data": base64.b64encode(hashlib.sha256(b"global:revoke_release_entry").digest()[:8]).decode(),
}
tmp = out + ".tmp"
with open(tmp, "w", encoding="utf-8") as f: json.dump(doc, f, sort_keys=True); f.write("\n")
os.chmod(tmp, 0o600); os.replace(tmp, out)
PY
  for ((i=1; i<=MEL_RELEASE_SQUADS_THRESHOLD; ++i)); do
    member="$(printenv "MEL_RELEASE_MEMBER_KEYPAIR_$i" 2>/dev/null || true)"
    [[ -n "$member" && -f "$member" && ! -L "$member" ]] || die "missing regular MEL_RELEASE_MEMBER_KEYPAIR_$i for revoke quorum"
    member_args+=(--member "$member")
  done
  result="$(SQUADS_MULTISIG="$MEL_RELEASE_SQUADS_MULTISIG" SQUADS_VAULT="$MEL_RELEASE_SQUADS_VAULT" \
    SQUADS_PROGRAM_ID="$MEL_RELEASE_SQUADS_PROGRAM_ID" MELUSINA_RPC_PRIMARY="$MEL_RELEASE_RPC_URL" \
    node "$executor" "$ix" --multisig "$MEL_RELEASE_SQUADS_MULTISIG" --vault "$MEL_RELEASE_SQUADS_VAULT" "${member_args[@]}")"
  sig="$(python3 - "$result" <<'PY'
import json, sys
for line in reversed(sys.argv[1].splitlines()):
    try:
        doc=json.loads(line)
    except json.JSONDecodeError:
        continue
    if doc.get("status") == "executed" and isinstance(doc.get("signature"), str) and doc["signature"]:
        print(doc["signature"]); break
else:
    raise SystemExit("Squads revoke did not return an executed signature")
PY
)"
  python3 - "$MEL_REVOKE_RECEIPT_OUT" "$MEL_PDA" "$sig" <<'PY'
import json, os, sys
out, pda, sig = sys.argv[1:]
tmp = out + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump({"schema":"melusina-revoke-release-receipt-v1","releaseEntryPda":pda,
               "status":"Revoked","transactionSignature":sig}, f, sort_keys=True); f.write("\n")
os.chmod(tmp, 0o600); os.replace(tmp, out)
PY
}

served_app_hash() {
  need MEL_APP_ID; need MEL_RELEASE_STORE_URL
  python3 - "$MEL_RELEASE_STORE_URL" "$MEL_APP_ID" <<'PY'
import json, sys, urllib.request
url, app = sys.argv[1].rstrip("/") + "/apps/index.json", sys.argv[2]
with urllib.request.urlopen(url, timeout=20) as r: doc = json.load(r)
items = doc.get("apps", doc if isinstance(doc, list) else [])
hits = [x for x in items if isinstance(x, dict) and x.get("appId") == app]
if len(hits) > 1: raise SystemExit("ambiguous catalog appId")
if hits:
    item = hits[0]
    # The signed store catalog binds the release authority under attest; older
    # fixtures exposed appHash at the top level. Accept either representation,
    # but never infer a hash from another app or a package filename.
    value = item.get("appHash", "")
    if not value and isinstance(item.get("attest"), dict):
        value = item["attest"].get("appHash", "")
    print(value)
PY
}

stage() {
  need MEL_APP_ID; need MEL_NEW_APP_HASH; need MEL_RELEASE_HASH; need MEL_NEW_VERSION; need MEL_RELEASE_NONCE; need MEL_STAGE_RECEIPT_OUT
  need MEL_RELEASE_MASTER_NFT_MINT; need MEL_RELEASE_STORE_LICENSE_MINT; need MEL_RELEASE_STORE_DOMAIN
  need MEL_RELEASE_STORE_URL; need MEL_RELEASE_STORE_PUBKEY; need MEL_RELEASE_RPC_URL; need MEL_RELEASE_PUBLISHER_KEY
  local state release runtime_contract runtime_sha
  state="$(app_dir_for)"
  [[ -f "$state/material/app.spk" && -f "$state/material/metadata.json" ]] || die "no built material; run publish/build first"
  assert_runtime_contract_frozen "$state" "$MEL_APP_ID" "$MEL_NEW_VERSION" "$MEL_NEW_APP_HASH"
  runtime_contract="$state/material/RUNTIME-CONTRACT.json"
  runtime_sha="$(sha256sum "$runtime_contract" | awk '{print $1}')"
  release="$state/release-stage.json"
  python3 - "$release" "$MEL_NEW_APP_HASH" "$MEL_RELEASE_HASH" "$MEL_NEW_VERSION" "$MEL_RELEASE_NONCE" "$MEL_RELEASE_MASTER_NFT_MINT" "$RUNTIME_CONTRACT_SCHEMA" "$runtime_sha" <<'PY'
import json, os, sys
out, apphash, rhash, ver, nonce, master, runtime_schema, runtime_sha = sys.argv[1:]
doc={"$schema":"melusina-release-v1","appHash":apphash,"releaseHash":rhash,"version":ver,
     "signedAtUnix":0,"masterNftMint":master,"licenseSquadsVault":"","releaseEntryPda":"",
     "authorSig":"","quorumPolicy":{"threshold":0,"memberCount":0,"multisigPda":""},"releaseNonce":nonce,
     "runtimeContractSchema":runtime_schema,"runtimeContractSha256":runtime_sha}
with open(out,"w",encoding="utf-8") as f: json.dump(doc,f,sort_keys=True);f.write("\n")
os.chmod(out,0o600)
PY
  catalog_slot_args
  submit_cmd --store "$MEL_RELEASE_STORE_URL" --spk "$state/material/app.spk" --metadata "$state/material/metadata.json" \
    --release "$release" --runtime-contract "$runtime_contract" --publisher-key "$MEL_RELEASE_PUBLISHER_KEY" --store-pubkey "$MEL_RELEASE_STORE_PUBKEY" \
    --license-mint "$MEL_RELEASE_STORE_LICENSE_MINT" --domain "$MEL_RELEASE_STORE_DOMAIN" --rpc-url "$MEL_RELEASE_RPC_URL" \
    "${SUBMIT_CATALOG_SLOT_ARGS[@]}" --stage --receipt-out "$MEL_STAGE_RECEIPT_OUT"
}

need_ceremony_env() {
  need MEL_APP_ID; need MEL_NEW_APP_HASH; need MEL_NEW_VERSION; need MEL_RELEASE_NONCE
  need MEL_RELEASE_LICENSE_MINT; need MEL_RELEASE_MASTER_NFT_MINT; need MEL_RELEASE_SQUADS_MULTISIG; need MEL_RELEASE_SQUADS_VAULT
  need MEL_RELEASE_SQUADS_THRESHOLD; need MEL_RELEASE_SQUADS_MEMBER_COUNT; need MEL_RELEASE_SQUADS_PROGRAM_ID
  need_file MEL_RELEASE_AUTHOR_KEYPAIR; need_file MEL_RELEASE_MEMBER_KEYPAIR_1; need MEL_RELEASE_RPC_URL
  need_executable MEL_RELEASE_PEARL_TOOL
  [[ "$MEL_RELEASE_SQUADS_THRESHOLD" =~ ^[1-9][0-9]*$ ]] || die "MEL_RELEASE_SQUADS_THRESHOLD must be positive integer"
  [[ "$MEL_RELEASE_SQUADS_MEMBER_COUNT" =~ ^[1-9][0-9]*$ ]] || die "MEL_RELEASE_SQUADS_MEMBER_COUNT must be positive integer"
  (( MEL_RELEASE_SQUADS_MEMBER_COUNT >= MEL_RELEASE_SQUADS_THRESHOLD )) || die "Squads member count is below threshold"
  local available=0 i
  for ((i=1; i<=16; ++i)); do
    [[ -n "$(printenv "MEL_RELEASE_MEMBER_KEYPAIR_$i" 2>/dev/null || true)" ]] && ((available+=1))
  done
  (( available >= MEL_RELEASE_SQUADS_THRESHOLD )) || die "only $available member keypairs configured for threshold $MEL_RELEASE_SQUADS_THRESHOLD"
  need_dir MEL_RELEASE_NODE_MODULES
  [[ -f "$MEL_RELEASE_NODE_MODULES/@solana/web3.js/package.json" ]] || die "MEL_RELEASE_NODE_MODULES must contain @solana/web3.js"
  [[ -f "$MEL_RELEASE_NODE_MODULES/@sqds/multisig/package.json" ]] || die "MEL_RELEASE_NODE_MODULES must contain @sqds/multisig"
  [[ -f "$NODE_HELPER" && ! -L "$NODE_HELPER" ]] || die "provider node helper missing"
}

propose_register() {
  need MEL_RELEASE_JSON_OUT; need MEL_PROPOSE_RECEIPT_OUT
  need_ceremony_env
  local state material_release ceremony lockfd index runtime_contract runtime_sha
  state="$(app_dir_for)"; material_release="$state/release.json"; ceremony="$state/ceremony-state.json"
  [[ -f "$state/material/app.spk" && -f "$state/material/metadata.json" ]] || die "no built material; run publish/build first"
  assert_runtime_contract_frozen "$state" "$MEL_APP_ID" "$MEL_NEW_VERSION" "$MEL_NEW_APP_HASH"
  runtime_contract="$state/material/RUNTIME-CONTRACT.json"
  runtime_sha="$(sha256sum "$runtime_contract" | awk '{print $1}')"
  mkdir -p "$state"
  exec {lockfd}>"$MEL_RELEASE_STATE_DIR/locks/squads-${MEL_RELEASE_SQUADS_MULTISIG}.lock"
  flock -w "${MEL_RELEASE_LOCK_WAIT_SECS:-600}" "$lockfd" || die "timed out waiting for this Squads multisig ceremony lock"
  index="$(node "$NODE_HELPER" next-index)"
  [[ "$index" =~ ^[0-9]+$ ]] || die "Squads next transaction index is malformed"
  python3 - "$material_release" "$MEL_NEW_APP_HASH" "$MEL_RELEASE_HASH" "$MEL_NEW_VERSION" "$MEL_RELEASE_NONCE" "$MEL_RELEASE_MASTER_NFT_MINT" "$RUNTIME_CONTRACT_SCHEMA" "$runtime_sha" <<'PY'
import json, os, sys
out, apphash, rhash, ver, nonce, master, runtime_schema, runtime_sha = sys.argv[1:]
doc={"$schema":"melusina-release-v1","appHash":apphash,"releaseHash":rhash,"version":ver,
     "signedAtUnix":0,"masterNftMint":master,"licenseSquadsVault":"","releaseEntryPda":"",
     "authorSig":"","quorumPolicy":{"threshold":0,"memberCount":0,"multisigPda":""},"releaseNonce":nonce,
     "runtimeContractSchema":runtime_schema,"runtimeContractSha256":runtime_sha}
with open(out,"w",encoding="utf-8") as f: json.dump(doc,f,sort_keys=True);f.write("\n")
os.chmod(out,0o600)
PY
  "$MEL_RELEASE_PEARL_TOOL" propose-release --dry-run --app-dir "$state/pearl-material" --release-json "$material_release" \
    --license-mint "$MEL_RELEASE_LICENSE_MINT" --master-mint "$MEL_RELEASE_MASTER_NFT_MINT" \
    --version "$MEL_NEW_VERSION" --app-id "$MEL_APP_ID" --state-out "$ceremony" \
    --program-id "$MEL_PROGRAM_ID" --Squads-program-id "$MEL_RELEASE_SQUADS_PROGRAM_ID" \
    --multisig "$MEL_RELEASE_SQUADS_MULTISIG" --vault "$MEL_RELEASE_SQUADS_VAULT" \
    --quorum-threshold "$MEL_RELEASE_SQUADS_THRESHOLD" --quorum-member-count "$MEL_RELEASE_SQUADS_MEMBER_COUNT" \
    --author-keypair "$MEL_RELEASE_AUTHOR_KEYPAIR" --transaction-index "$index"
  node "$NODE_HELPER" propose "$ceremony" >"$state/proposal-result.json"
  python3 - "$ceremony" "$material_release" "$MEL_RELEASE_JSON_OUT" "$MEL_PROPOSE_RECEIPT_OUT" "$MEL_RELEASE_SQUADS_MULTISIG" "$MEL_RELEASE_SQUADS_VAULT" "$RUNTIME_CONTRACT_SCHEMA" "$runtime_sha" <<'PY'
import json, os, shutil, sys
state_path, release_path, out_release, out_receipt, multisig, vault, runtime_schema, runtime_sha = sys.argv[1:]
st=json.load(open(state_path,encoding="utf-8")); result=json.load(open(state_path.rsplit('/',1)[0]+"/proposal-result.json",encoding="utf-8"))
doc=json.load(open(release_path,encoding="utf-8"))
doc["releaseEntryPda"] = st["releaseEntryPda"]
doc["licenseSquadsVault"] = st["licenseSquadsVault"]
doc["authorSig"] = st["authorSig"]
doc["quorumPolicy"] = st["quorumPolicy"]
doc["runtimeContractSchema"] = runtime_schema
doc["runtimeContractSha256"] = runtime_sha
for path, value in ((out_release,doc),(out_receipt,{"schema":"melusina-register-proposal-receipt-v1","releaseEntryPda":st["releaseEntryPda"],"transactionPda":st["transactionPda"],"multisig":multisig,"vault":vault,"instruction":"register_release_entry","status":"Proposed","proposalPda":st["proposalPda"],"transactionIndex":st["transactionIndex"],"proposalCreateSignature":result["proposalCreateSignature"],"vaultTransactionCreateSignature":result["vaultTransactionCreateSignature"]})):
    os.makedirs(os.path.dirname(path),exist_ok=True); tmp=path+".tmp"
    with open(tmp,"w",encoding="utf-8") as f: json.dump(value,f,sort_keys=True);f.write("\n")
    os.chmod(tmp,0o600);os.replace(tmp,path)
PY
}

approve_register() {
  need MEL_APP_ID; need MEL_TRANSACTION_PDA; need MEL_REGISTER_RECEIPT_OUT; need MEL_FINAL_RELEASE_JSON_OUT
  need_ceremony_env
  local state ceremony release result runtime_contract runtime_sha release_runtime_schema release_runtime_sha
  state="$(app_dir_for)"; ceremony="$state/ceremony-state.json"; release="$state/release.json"; result="$state/approve-result.json"
  [[ -f "$ceremony" && -f "$release" ]] || die "no persisted unexecuted release proposal for this app"
  [[ "$(json_get "$ceremony" transactionPda)" = "$MEL_TRANSACTION_PDA" ]] || die "MEL_TRANSACTION_PDA does not bind the persisted proposal"
  assert_runtime_contract_frozen "$state" "$MEL_APP_ID" "$MEL_NEW_VERSION" "$MEL_NEW_APP_HASH"
  runtime_contract="$state/material/RUNTIME-CONTRACT.json"
  runtime_sha="$(sha256sum "$runtime_contract" | awk '{print $1}')"
  release_runtime_schema="$(json_get "$release" runtimeContractSchema)"
  release_runtime_sha="$(json_get "$release" runtimeContractSha256)"
  [[ "$release_runtime_schema" = "$RUNTIME_CONTRACT_SCHEMA" && "$release_runtime_sha" = "$runtime_sha" ]] || die "proposed RELEASE.json runtime-contract claims drifted"
  node "$NODE_HELPER" approve-execute "$ceremony" >"$result"
  "$MEL_RELEASE_PEARL_TOOL" finalize-release --app-dir "$state/pearl-material" --release-json "$release" --state "$ceremony" --rpc-url "$MEL_RELEASE_RPC_URL" --program-id "$MEL_PROGRAM_ID"
  # The installed Pearl finalizer rewrites the fields it understands. Restore
  # only the exact claims captured and rechecked above; promotion's Go validator
  # then proves them against the same frozen contract bytes.
  python3 - "$release" "$release_runtime_schema" "$release_runtime_sha" <<'PY'
import json, os, sys
path, runtime_schema, runtime_sha = sys.argv[1:]
doc = json.load(open(path, encoding="utf-8"))
doc["runtimeContractSchema"] = runtime_schema
doc["runtimeContractSha256"] = runtime_sha
tmp = path + ".runtime-contract.tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, sort_keys=True); fh.write("\n")
os.chmod(tmp, 0o600); os.replace(tmp, path)
PY
  "$MEL_RELEASE_PEARL_TOOL" verify-release --spk "$state/pearl-material/app.spk" --metadata "$state/pearl-material/metadata.json" --release-json "$release" --app-slug "$MEL_APP_ID"
  python3 - "$ceremony" "$release" "$result" "$MEL_FINAL_RELEASE_JSON_OUT" "$MEL_REGISTER_RECEIPT_OUT" <<'PY'
import json, os, sys
state_path, release_path, result_path, release_out, receipt_out=sys.argv[1:]
st=json.load(open(state_path,encoding="utf-8")); res=json.load(open(result_path,encoding="utf-8")); release=json.load(open(release_path,encoding="utf-8"))
for path, value in ((release_out,release),(receipt_out,{"schema":"melusina-register-release-receipt-v1","releaseEntryPda":st["releaseEntryPda"],"releaseHash":st["releaseHash"],"status":"Active","alreadyRegistered":bool(res.get("alreadyExecuted",False)),"transactionSignatures":res.get("transactionSignatures",[])})):
    os.makedirs(os.path.dirname(path),exist_ok=True); tmp=path+".tmp"
    with open(tmp,"w",encoding="utf-8") as f: json.dump(value,f,sort_keys=True);f.write("\n")
    os.chmod(tmp,0o600);os.replace(tmp,path)
PY
}

promote() {
  need MEL_APP_ID; need MEL_NEW_APP_HASH; need MEL_RELEASE_HASH; need MEL_NEW_VERSION; need MEL_STAGE_ID; need MEL_PROMOTE_RECEIPT_OUT
  need MEL_RELEASE_STORE_LICENSE_MINT; need MEL_RELEASE_STORE_DOMAIN
  need MEL_RELEASE_STORE_URL; need MEL_RELEASE_STORE_PUBKEY; need MEL_RELEASE_RPC_URL; need MEL_RELEASE_PUBLISHER_KEY
  local state release runtime_contract runtime_sha
  state="$(app_dir_for)"; release="$state/release.json"
  [[ -f "$state/material/app.spk" && -f "$state/material/metadata.json" && -f "$release" ]] || die "promotion material or finalized release JSON is missing"
  [[ "$(json_get "$release" appHash)" = "$MEL_NEW_APP_HASH" ]] || die "final release appHash differs from promotion request"
  [[ "$(json_get "$release" releaseHash)" = "$MEL_RELEASE_HASH" ]] || die "final release hash differs from promotion request"
  assert_runtime_contract_frozen "$state" "$MEL_APP_ID" "$MEL_NEW_VERSION" "$MEL_NEW_APP_HASH"
  runtime_contract="$state/material/RUNTIME-CONTRACT.json"
  runtime_sha="$(sha256sum "$runtime_contract" | awk '{print $1}')"
  [[ "$(json_get "$release" runtimeContractSchema)" = "$RUNTIME_CONTRACT_SCHEMA" ]] || die "final release runtimeContractSchema differs from the frozen candidate"
  [[ "$(json_get "$release" runtimeContractSha256)" = "$runtime_sha" ]] || die "final release runtimeContractSha256 differs from the frozen candidate"
  catalog_slot_args
  submit_cmd --store "$MEL_RELEASE_STORE_URL" --spk "$state/material/app.spk" --metadata "$state/material/metadata.json" \
    --release "$release" --runtime-contract "$runtime_contract" --publisher-key "$MEL_RELEASE_PUBLISHER_KEY" --store-pubkey "$MEL_RELEASE_STORE_PUBKEY" \
    --license-mint "$MEL_RELEASE_STORE_LICENSE_MINT" --domain "$MEL_RELEASE_STORE_DOMAIN" --rpc-url "$MEL_RELEASE_RPC_URL" \
    "${SUBMIT_CATALOG_SLOT_ARGS[@]}" --receipt-out "$MEL_PROMOTE_RECEIPT_OUT"
}

case "$OP" in
  build) build ;;
  active-releases) active_releases ;;
  release-status) release_status ;;
  served-app-hash) served_app_hash ;;
  stage) stage ;;
  propose-register) propose_register ;;
  approve-register) approve_register ;;
  promote) promote ;;
  revoke) revoke ;;
esac
