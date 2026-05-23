# cca.sh Domain Template

The Domain Template grain is the single source of truth for all domain-specific
configuration in the cca.sh constellation: workflow definitions, account
profiles, portal layouts, datasets, hook recipes, welcome/intake questionnaires,
and static assets.

Runtime grains (Station, Process, Account, Clientspace) start virgin and
hydrate their configuration from the Template grain via Powerbox capability
offer. No domain logic lives in Go code — it lives in domain packs served by
this grain.

## Domain packs

One Template grain can serve many domains (ccash, openclaw, telescreen, …).
Each domain pack is a file-backed bundle containing station profiles, account
profiles, portal profiles, datasets, provider configs, risk config, welcome
flows, and assets. Domain packs ship embedded inside the grain and are seeded
into writable storage on first boot; operators can edit them from the admin UI.

## Capabilities exposed

- **TemplateService** — full enumerate/read surface.
- **DomainSelection** — scoped to one domain.
- **StationTemplateSelection** — scoped to a (domain, stationProfile) pair.

All three are durable (AppPersistent) and offered over Powerbox.
