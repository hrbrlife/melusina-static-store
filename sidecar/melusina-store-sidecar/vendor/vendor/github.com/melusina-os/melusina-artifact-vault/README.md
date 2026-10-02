# Melusina Bazaar artifact vault

This is the private, immutable artifact boundary for the Bazaar Control build,
preparation, and finalization workers. It is intentionally not part of the
Pearl, Store Link, public Bazaar, terminal handoff, or sidecar HTTP surface.

## Human meaning

Operators should see one requirement: **the release worker custody service is
healthy**. They never choose an artifact path, send artifact bytes, run a vault
command during release, or copy a candidate between workers.

The worker sequence is automatic:

```text
trusted build stores candidate
  -> preparation reopens that exact candidate and stores finalization input
  -> finalization reopens both and stores the final sidecar body
```

Each operation addresses an object solely by its SHA-256 plus exact byte count.
The vault never lists, replaces, deletes, or accepts an object path from a
caller.

## Identity boundary

The daemon owns a mode-0700 object root and mode-0600 object files. Workers do
not mount that directory. They connect only to a configured mode-0660 Unix
socket under a mode-0710 runtime directory. `SO_PEERCRED` must match a
deployer-owned allowlist of the distinct trusted-build, preparation, and
finalization service UIDs. The shared socket group permits a connection but is
not authorization.

The daemon has no TCP listener, HTTP handler, route, token, callback, source
path, shell command, app selector, or transaction signer. A terminal, LLM,
Pearl, browser, app grain, Store Link, and sidecar are not allowed peers.

## Configuration and service

The deployer writes `/etc/bazaar-artifact-vault/config.json` as a vault-user
owned mode-0600 exact JSON document with this shape:

```json
{
  "schema": "melusina-artifact-vault-config-v1",
  "root": "/var/lib/bazaar-artifact-vault",
  "socketPath": "/run/bazaar-artifact-vault/vault.sock",
  "socketGroupId": 1234,
  "allowedPeerUids": [1101, 1102, 1103],
  "maxObjectBytes": 67108864
}
```

The numeric IDs above are examples, not defaults. The deployer must create
distinct service accounts and explicitly set the real IDs. The included systemd
unit is a source asset only; it is not installed or enabled by this repository.
Before a pilot, verify a refused peer cannot connect, an allowed build identity
can store one candidate, the preparation/finalizer identities can read only its
descriptor, and a tampered on-disk object fails closed.
