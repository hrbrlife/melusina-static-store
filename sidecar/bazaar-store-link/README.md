# Bazaar Store Link

`bazaar-store-link` is the small, host-operated connector between a contained
Bazaar Control Pearl and the Store sidecar's private control listener. It makes
the release flow human-sized without turning the Store into a public signing or
transaction service.

```text
terminal agent --submit capability--> Bazaar Control Pearl
human offline approval -------------> Bazaar Control Pearl
Pearl --selected Sandstorm HTTP-out capability--> Bazaar Store Link
Bazaar Store Link --pinned mTLS--> Store sidecar
Store sidecar --Unix socket--> listing signer
```

The connector currently exposes exactly this fixed vocabulary:

- `POST /v1/release-commands/<24-lower-hex>/prepare`
- `POST /v1/release-commands/<24-lower-hex>/publish`
- `GET /v1/authority/<configured-store>/<app>/<publisher>`
- `GET /v1/store-status` (read-only control-path readiness only)
- `POST /v1/build-jobs`, `GET /v1/build-jobs/<24-lower-hex>`
- `POST /v1/release-preparation-jobs`, `GET /v1/release-preparation-jobs/<24-lower-hex>`
- `POST /v1/release-finalization-jobs`, `GET /v1/release-finalization-jobs/<24-lower-hex>`
- `POST /v1/tenant-proof-jobs`, `GET /v1/tenant-proof-jobs/<24-lower-hex>`
- `POST /v1/tenant-proof-jobs/<24-lower-hex>/resume`

It cannot accept a caller-chosen URL, method, sidecar path, transaction,
signing request, artifact body/path/URL, publisher lifecycle request, generic
RPC call, or listing instruction. It maps release/authority operations to the
typed sidecar routes only, and forwards build/proof jobs to separately
configured worker origins only. Finalization jobs carry a committed candidate
SHA-256 and byte count, not candidate bytes; the finalizer retrieves that exact
object from its fixed content-addressed artifact vault. For release commands it forwards only `Content-Type`, the Pearl command,
Pearl signature, and—for publication—the offline approval. The sidecar still
verifies the same command, publisher grant, artifact, chain facts, predecessor,
and listing-before-selector rule independently.

`GET /v1/store-status` is not a generic health proxy. It maps only to the
sidecar's private mTLS control status, requires the exact configured Store ID,
and relays only its fixed `ready` schema. It neither claims the public catalog
is readable nor exposes release, chain, endpoint, or key facts.

The proof-resume route is deliberately not a generic job action. It accepts
only the exact `bazaar-control-tenant-proof-resume-request-v1` body containing
the existing dossier ID and release digest, and forwards it only to the pinned
proof worker. The worker independently requires that the named job is already
`Needs attention` and that those facts match its durable record. It returns a
job acknowledgement or the same visible `Needs attention` state; the Pearl
must poll the signed attestation separately before marking a release live.

## Deployment boundary

The connector is an operator service next to the Store, not code inside the
Pearl SPK. Its configuration names a private listener and the private sidecar
origin plus paths to its client certificate, private key, and sidecar CA. Those
credentials must be created by the Store operator and are never copied into a
Pearl, terminal, build worker, browser, or package.

Example shape (use real protected paths; do not commit this file):

```json
{
  "listenAddr": "10.53.155.42:9460",
  "storeId": "melusina-os-root-store",
  "sidecarUrl": "https://127.0.0.1:9443",
  "clientCertPath": "/etc/bazaar-store-link/client.pem",
  "clientKeyPath": "/etc/bazaar-store-link/client.key",
  "sidecarCaPath": "/etc/bazaar-store-link/sidecar-ca.pem",
  "buildWorkerUrl": "https://127.0.0.1:9461",
  "releasePreparationWorkerUrl": "https://127.0.0.1:9463",
  "releaseFinalizationWorkerUrl": "https://127.0.0.1:9464",
  "tenantProofWorkerUrl": "https://127.0.0.1:9462",
  "workerCaPath": "/etc/bazaar-store-link/worker-ca.pem"
}
```

The listener must be restricted at the host firewall to Sandstorm's outbound
service path. That network rule protects availability; it is not release
authority. The actual mutation gate is the independently verified, expiring,
single-use Pearl command plus the exact offline approval.

Run the service only after the sidecar has a dedicated TLS-1.3 control listener
configured with this connector's exact client-leaf digest:

```text
bazaar-store-link -config /etc/bazaar-store-link/config.json
```

## Current status

This source is a verified connector boundary and durable-job relay, **not a
deployed Golden MVP**. It requires separately implemented and deployed bounded
build, release-preparation, release-finalization, and tenant-proof workers,
which must persist their own jobs and return release-bound signed results. The
finalizer also needs a configured immutable content-addressed artifact vault;
the relay must never become its artifact transport. The relay intentionally
rejects startup without the worker origins and their CA. Do not switch
`require_pearl_control_for_app_publish` on a live Store until the complete
provisioning and one-app pilot in Bazaar Control's deployment requirements have
passed.
