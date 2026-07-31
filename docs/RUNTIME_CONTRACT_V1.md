# Runtime-contract v1

An on-chain `ReleaseEntry` proves which SPK and `metadata.json` bytes may be
served. It does not prove that an installed app opens, reaches a sidecar, trusts
TLS, or completes its first real job. Runtime-contract v1 makes that second
requirement explicit for every future Bazaar publication.

This is deliberately a **declaration and test plan**, not a fake green tick.
The visible Store labels a contract-bearing release `runtime proof pending` until
a separate clean-install, visible-UI acceptance run has recorded the real
launch and functional result. A historical card with no contract is labelled
`runtime uncertified`; it is never silently promoted to a pass.

## Artifacts and binding

A future app release contains these four files:

```text
app.spk
metadata.json
RELEASE.json
RUNTIME-CONTRACT.json
```

The binding is intentionally layered:

```text
exact app.spk + metadata.json ──> ReleaseEntry.appHash (on chain)
exact RELEASE.json              ──> publisher-signed publish envelope
exact RUNTIME-CONTRACT.json     ──> RELEASE.json.runtimeContractSha256
exact app.spk                   ──> contract.app.spkSha256
```

The current Pearl finalizer writes only the on-chain manifest fields. After it
has finalized and verified the registered release, attach both fields below and
validate the four artifacts. This must happen before the submit client signs
and uploads the exact publisher envelope:

```json
{
  "runtimeContractSchema": "melusina-app-runtime-contract-v1",
  "runtimeContractSha256": "<lower-case sha256 of raw RUNTIME-CONTRACT.json bytes>"
}
```

The receiving store validates all four links before persisting a new publish.
It persists the contract beside the release and serves it at:

```text
/attest/<appId>/RUNTIME-CONTRACT.json
```

At serve time, a release that claims a contract but has a missing, altered, or
malformed contract is refused. A real pre-contract release remains readable
through the normal on-chain SPK gate and is explicitly reported as
`uncertified`.

## Required contract shape

The canonical JSON Schema is published with every catalog at:

```text
/schemas/melusina-app-runtime-contract-v1.schema.json
```

The compact shape is:

```json
{
  "$schema": "https://bazaar.melusina-os.org/schemas/melusina-app-runtime-contract-v1.schema.json",
  "schema": "melusina-app-runtime-contract-v1",
  "app": {
    "appId": "<same as metadata.json>",
    "version": "<same as RELEASE.json>",
    "spkSha256": "<sha256 of exact app.spk>",
    "appHash": "<same as RELEASE.json.appHash>"
  },
  "sidecars": [
    {
      "id": "mermail",
      "host": "mermail.sidecar.host",
      "port": 8025,
      "transport": "https",
      "tls": {
        "required": true,
        "serverName": "mermail.sidecar.host",
        "trust": "system-ca",
        "minimumVersion": "TLS1.2"
      },
      "capabilities": ["http-out"],
      "safeProbe": {
        "action": "Use the visible Mail Station flow to send a controlled message to the test sink.",
        "expectedResult": "The app visibly reports success and the controlled sink receives the message."
      }
    }
  ],
  "launchProbe": {
    "kind": "visible-ui",
    "steps": [
      {
        "action": "Install from Bazaar and open the normal app action.",
        "expectedResult": "The normal UI renders without a 403, TLS error, reset, or blank failure page."
      }
    ],
    "expectedResult": "The app is usable through the normal UI."
  },
  "fixtures": [
    {
      "name": "controlled-mail-sink",
      "purpose": "Prove one reversible delivery operation.",
      "setup": "Provision it only for the acceptance run; do not include credentials in this contract."
    }
  ],
  "cleanup": {
    "steps": [
      "Delete the controlled message and temporary connection after the assertion."
    ]
  }
}
```

An app with no sidecar must explicitly use `"sidecars": []` and still provide
a visible launch probe, fixture declaration (`[]` is valid), and cleanup plan.

## Endpoint safety rules

Sidecars are a closed endpoint tuple, not a URL string:

```text
https + exact canonical host + explicit TCP port
```

The only permitted host tiers are:

```text
<name>.sidecar.host
<name>.sidecar.hypervisor
<name>.sidecar.hypervisor.shared
<name>.sidecar.local
<name>.sidecar.remote
<name>.sidecar.remote.shared
```

This supports the actual topology—such as `mermail.sidecar.host:8025` and
`vintage.sidecar.hypervisor:443`—without allowing an arbitrary Internet URL,
scheme downgrade, path/query injection, wildcard, IP literal, `localhost`, or
TLS verification bypass. Every declared sidecar must use `https`, `system-ca`
trust, an exact SNI server name equal to its declared host, TLS 1.2 or newer,
and an explicit `http-out` capability.

The deployment acceptance runner must independently compare each declared
host/port with the enabled target sidecar inventory, DNS/hosts mapping,
certificate chain, HTTP-out permission, and server-side blacklist policy. The
contract tells it what to prove; it never grants a network exception by itself.

## Publishing

Validate locally before a ceremony or upload:

```sh
python3 scripts/validate-runtime-contract.py \
  --contract path/to/RUNTIME-CONTRACT.json \
  --spk path/to/app.spk \
  --metadata path/to/metadata.json \
  --release path/to/RELEASE.json
```

Then submit the same artifact explicitly:

```sh
go run ./sidecar/melusina-store-sidecar/cmd/submit \
  --spk path/to/app.spk \
  --metadata path/to/metadata.json \
  --release path/to/RELEASE.json \
  --runtime-contract path/to/RUNTIME-CONTRACT.json \
  ...the normal publisher/store arguments...
```

The store accepts the JSON field `runtime_contract_b64` or the multipart file
part `runtime_contract`. Missing contracts, a hash mismatch, an app/SPK mismatch,
an insecure endpoint, or a contract whose stated test has no cleanup plan are
hard publish failures.

## What still makes an app verified

Publishing a correct contract is necessary but not sufficient. A release earns
an actual launch/function pass only when a clean target records all of these:

1. The administrator installed it from the visible Bazaar UI.
2. The app launched through its visible normal action without a 403, reset, TLS
   failure, blank page, or synthetic/direct-grain workaround.
3. Every declared sidecar was reached using its declared canonical endpoint and
   completed its declared safe operation.
4. The expected result appeared in the app or controlled fixture.
5. The declared cleanup completed.

That acceptance evidence belongs to the target test report, not inside the
release contract or package. No secret, bearer token, private endpoint, or
recovery data belongs in `RUNTIME-CONTRACT.json`.
