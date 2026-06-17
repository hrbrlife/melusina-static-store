#!/usr/bin/env python3
"""Reproduce the store-sidecar serve-gate's apphash.Canonical check for EVERY
served SPK in a dist-publish tree, exactly as serve_gate.go does:

  apps/index.json -> (packageId, appId)
  served SPK    = packages/<packageId>
  metadata.json = signatures/<appId>/metadata.json   (the ceremony's exact bytes)
  claim appHash = attest/<appId>/RELEASE.json .appHash (the on-chain-anchored value)

  computed = apphash.Canonical(served_spk, served_metadata)
           = sha256( sha256("F app.spk\0"+spk_bytes) ++ sha256("F metadata.json\0"+meta_bytes) )

PASS iff computed == claim appHash. Reports N/total and lists every miss.
"""
import hashlib, os, json, sys

DIST = sys.argv[1] if len(sys.argv) > 1 else "dist-publish"

def canonical(spk_path, meta_bytes):
    # files sorted by rel path: "app.spk" < "metadata.json"
    entries = [("app.spk", None, spk_path), ("metadata.json", meta_bytes, None)]
    entries.sort(key=lambda x: x[0])
    outer = hashlib.sha256()
    for rel, data, path in entries:
        inner = hashlib.sha256()
        inner.update(b"F ")
        inner.update(rel.encode())
        inner.update(b"\x00")
        if path is not None:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    inner.update(chunk)
        else:
            inner.update(data)
        outer.update(inner.digest())
    return outer.hexdigest()

idx_path = os.path.join(DIST, "apps", "index.json")
idx = json.load(open(idx_path))
apps = idx.get("apps", idx if isinstance(idx, list) else [])

total = 0
ok = 0
misses = []
offline = []
for app in apps:
    appid = (app.get("appId") or "").strip()
    pkgid = (app.get("packageId") or "").strip().lower()
    name = app.get("name", "?")
    ver = app.get("version", "?")
    if not appid or not pkgid:
        misses.append(f"{name} v{ver}: missing appId/packageId in index")
        total += 1
        continue
    spk = os.path.join(DIST, "packages", pkgid)
    rel_path = os.path.join(DIST, "attest", appid, "RELEASE.json")
    meta_path = os.path.join(DIST, "signatures", appid, "metadata.json")
    total += 1
    if not os.path.isfile(spk):
        misses.append(f"{name} v{ver} [{appid[:10]}]: served SPK packages/{pkgid} MISSING")
        continue
    if not os.path.isfile(rel_path):
        misses.append(f"{name} v{ver} [{appid[:10]}]: attest RELEASE.json MISSING")
        continue
    if not os.path.isfile(meta_path):
        misses.append(f"{name} v{ver} [{appid[:10]}]: signatures metadata.json MISSING")
        continue
    rel = json.load(open(rel_path))
    claim = (rel.get("appHash") or "").strip().lower()
    epda = (rel.get("releaseEntryPda") or "").strip()
    meta_bytes = open(meta_path, "rb").read()
    computed = canonical(spk, meta_bytes)
    anchored = bool(epda) and not epda.startswith("offline-")
    if not anchored:
        offline.append(f"{name} v{ver} [{appid[:10]}]: releaseEntryPda={epda!r} (NOT on-chain-anchored)")
    if computed == claim:
        ok += 1
    else:
        misses.append(f"{name} v{ver} [{appid[:10]}]: computed={computed[:16]}… != claim={claim[:16]}… (anchored={anchored})")

print(f"=== SERVE-GATE apphash.Canonical verification over {DIST} ===")
print(f"RESULT: {ok}/{total} served SPKs match their on-chain ReleaseEntry appHash")
if offline:
    print(f"\n-- {len(offline)} not on-chain-anchored (offline/empty releaseEntryPda):")
    for m in offline:
        print("   " + m)
if misses:
    print(f"\n-- {len(misses)} MISMATCH/MISSING:")
    for m in misses:
        print("   " + m)
else:
    print("\nAll served SPKs verified against on-chain-anchored appHash.")
sys.exit(0 if ok == total and total > 0 else 1)
