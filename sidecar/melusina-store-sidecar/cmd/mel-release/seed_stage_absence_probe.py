"""Read-only, fail-closed Stage absence probe for mel-release reconciliation.

The outer host is authenticated by its pinned SSH key. Its libvirt QGA runs
the inner read without an SSH server or key inside the Store. No guest file is
changed and no private bytes are returned.
"""

import argparse
import base64
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time


INNER = r'''
import json, os, re, stat, sys
app_id, pid = sys.argv[1:]
if not re.fullmatch(r"[a-z0-9]{52}", app_id) or not re.fullmatch(r"[1-9][0-9]*", pid):
    raise SystemExit("stage-absence-arguments-refused")
comm = open("/proc/" + pid + "/comm", encoding="utf-8").read().strip()
cmdline = open("/proc/" + pid + "/cmdline", "rb").read()
if not comm.startswith("melusina-store-") or b"/etc/melusina/store/store.config.json" not in cmdline:
    raise SystemExit("stage-absence-sidecar-identity-refused")
root = "/proc/" + pid + "/root/var/lib/melusina-store/private-app-candidates"
if not os.path.isdir(root):
    raise SystemExit("stage-absence-root-missing")
manifests = 0
matches = 0
with os.scandir(root) as entries:
    for entry in entries:
        if not re.fullmatch(r"[0-9a-f]{64}", entry.name):
            if entry.name.startswith(".tmp"):
                raise SystemExit("stage-absence-pending-write-refused")
            continue
        if not entry.is_dir(follow_symlinks=False):
            raise SystemExit("stage-absence-directory-refused")
        path = entry.path + "/stage.json"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            record = json.load(handle)
        if not isinstance(record, dict) or not re.fullmatch(r"[a-z0-9]{52}", record.get("appId", "")):
            raise SystemExit("stage-absence-manifest-invalid")
        manifests += 1
        matches += record["appId"] == app_id
if manifests < 2 or matches:
    raise SystemExit("stage-absence-not-proven")
print(json.dumps({"schema":"melusina.store-stage-absence.v1", "appId":app_id,
                  "sidecarPid":int(pid), "manifests":manifests, "targetMatches":matches}))
'''


def regular(path, private=False):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or (private and stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("stage-absence-credential-path-refused")


def qga(ssh, command):
    remote = "virsh -c qemu:///system qemu-agent-command d1f5-inner-store " + shlex.quote(
        json.dumps(command, separators=(",", ":")))
    output = subprocess.run(ssh + [remote], check=True, capture_output=True, text=True, timeout=20)
    data = json.loads(output.stdout)
    if set(data) != {"return"}:
        raise ValueError("stage-absence-qga-response-refused")
    return data["return"]


def run(app_id, key, known_hosts, port, sidecar_pid):
    if not re.fullmatch(r"[a-z0-9]{52}", app_id) or not 1 < sidecar_pid < 1 << 22 or not 1 < port < 65536:
        raise ValueError("stage-absence-arguments-refused")
    regular(key, private=True)
    regular(known_hosts)
    ssh = ["ssh", "-i", key, "-p", str(port), "-o", "IdentitiesOnly=yes",
           "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known_hosts,
           "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "root@127.0.0.1"]
    pid = qga(ssh, {"execute": "guest-exec", "arguments": {
        "path": "/usr/bin/python3", "arg": ["-c", INNER, app_id, str(sidecar_pid)],
        "capture-output": True}}).get("pid")
    if type(pid) is not int or pid <= 0:
        raise ValueError("stage-absence-qga-pid-refused")
    for _ in range(30):
        result = qga(ssh, {"execute": "guest-exec-status", "arguments": {"pid": pid}})
        if result.get("exited"):
            if result.get("exitcode") != 0 or result.get("err-data"):
                raise ValueError("stage-absence-qga-guest-refused")
            raw = base64.b64decode(result.get("out-data", ""), validate=True)
            value = json.loads(raw)
            if value != {"schema":"melusina.store-stage-absence.v1", "appId":app_id,
                         "sidecarPid":sidecar_pid, "manifests":value.get("manifests"), "targetMatches":0} \
                    or type(value.get("manifests")) is not int or value["manifests"] < 2:
                raise ValueError("stage-absence-qga-target-refused")
            return value
        time.sleep(0.1)
    raise ValueError("stage-absence-qga-timeout")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--outer-ssh-key", required=True)
    parser.add_argument("--outer-known-hosts", required=True)
    parser.add_argument("--outer-ssh-port", required=True, type=int)
    parser.add_argument("--sidecar-pid", required=True, type=int)
    opts = parser.parse_args()
    result = run(opts.app_id, opts.outer_ssh_key, opts.outer_known_hosts,
                 opts.outer_ssh_port, opts.sidecar_pid)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print("stage-absence-probe-refused: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
