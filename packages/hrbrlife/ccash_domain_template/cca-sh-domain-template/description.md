cca.sh Domain Template is the configuration authority for the cca.sh / popaye constellation. It owns the per-domain pack — workflow definitions, account profiles, portal layouts, datasets, hook recipes, intake questionnaires, static assets — that runtime Pearls hydrate at boot via Grapple. Runtime Pearls start virgin; everything customer-shaped lives here, edited as YAML.

## Why cca.sh Domain Template

- **Pinned domain-pack snapshots** — every release of a domain pack is hash-anchored to your Solana wallet; consuming Pearls can verify they're running the exact pack version you signed off on, not a silent server-side mutation. Compliance and auditors get cryptographic provenance, not a database query
- **Per-domain Pearl isolation** — one Template Pearl can serve many domains (ccash, openclaw, telescreen…) but each domain pack is sealed; cross-domain reads are physically impossible. A KYC misconfiguration in one domain cannot leak procedure logic into another
- **Editable in-place, no codegen** — operators edit YAML in the admin UI; the Template Pearl writes the changes to its sealed storage and signs the new version. No backend rebuild, no CI redeploy, no version-bump dance — change shows up in consuming Pearls on next handshake

## Capabilities exposed

- **TemplateService** — full enumerate/read surface across all domains served
- **DomainSelection** — scoped to one domain
- **StationTemplateSelection** — scoped to a (domain, stationProfile) pair

All three are durable (AppPersistent) and offered over Grapple.

## Status

*Pre-release v0.2.0.* Domain-pack authoring loop is live for the popaye whitelabel; multi-domain validation lands once a second whitelabel is authored without engine-side edits.
