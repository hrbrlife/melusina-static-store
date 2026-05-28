# Changelog

## 0.2.0 — 2026-04-15

- **Multi-sidecar endpoint selector on Step 0 (connectivity check).**
  The Connect-to-Sidecar card now shows a four-option picker for
  which Fineract-sidecar variant this grain should reach: `host`,
  `remote`, `hypervisor`, `hypervisor.shared`. Each
  variant has its own `Fineract.sidecar.{variant}` canonical URL
  and its own server-built packed Cap'n Proto PowerboxDescriptor, so
  the Sandstorm shell opens the address-selector popup scoped to
  exactly the URL the operator picked.
- **Pre-save reachability probe.** After the PowerBox grant lands
  and the capability is in hand, but BEFORE the FineractClient
  transport is swapped, the grain issues a probe GET through the
  just-claimed capability. On transport error or 5xx the claim is
  released and the UI reports the failure so the operator can
  re-pick a variant without clearing dead state.
- Switch the default canonical URL to `Fineract.sidecar.host`. The
  `.host` gateway route has a real TLS cert the shell trusts, which
  keeps HTTP-out proxy verification aligned with Melusina routing.

## 0.1.0

- Wired the `Fineract-setup` companion grain into a Sandstorm package
- Added `launcher.sh` + `sandstorm-pkgdef.capnp` using the ccash grain pattern
- Added package-level `make build`, `make dev`, `make spk`, `make pack`, and `make verify`
- Kept the Docker sidecar workflow available via `make docker-dev`
