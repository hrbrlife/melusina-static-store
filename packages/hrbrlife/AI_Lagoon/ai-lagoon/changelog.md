# AiLagoon Changelog

## v0.7.0 (2026-04-20)

- **Harmonise the stack on `melusina-http-component` + SQLite.** All
  Melusina grains are converging on ccash's encrypted-SQLite persistence
  stack (`grain-crypto-journal/sqlitestore`, pure-Go `modernc.org/sqlite`,
  AES-256-GCM at rest, idempotent migrations). AiLagoon is the first
  consumer of the new shared `melusina-http-component` module, which
  owns the Cap'n Proto `PowerboxDescriptor` builder, the 4-variant
  sidecar selector, and the Powerbox sturdyref lifecycle (Claim / Save
  / Restore / Release) for every grain going forward. Single source of
  truth replaces the three byte-identical copies that previously shipped
  across ai-lagoon, cyberteller, and the Melusina lab grains.
- **Sturdyref destruction on connection delete.** Deleting a connection
  now calls `SandstormApi.drop(token)` before removing the local row.
  Every prior Melusina grain leaked these persistent references — the
  shell kept the capability alive after the grain believed the
  connection was gone. This is a silent fix but a real capability-leak
  plug.
- **No more `/var/connections.json` and no more `/var/httpout_*`.**
  Connection records and Powerbox tokens both live in the grain's
  SQLite database at `/var/ailagoon.db`. The database schema is
  encryption-ready (the shared `grain-crypto-journal/sqlitestore`
  supports AES-256-GCM at rest via a keybox-wrapped DEK), but the
  Encryptor is intentionally unwired in v0.7.0 — the master-key
  derivation flow is being ported from ccash and will land in v0.8.
  Until then, `/var/ailagoon.db` is plaintext inside the grain's
  Sandstorm sandbox boundary. There is no migration path from the
  old JSON/file-token shape — fresh install on every upgrade.
  Pre-existing grains will present an empty connections list and a
  clean slate.
- Removed the `pkg/httpout/` in-grain copy and the `*.PowerboxToken`
  field on `connections.Connection`; both shifted into the shared module.
- `connections.Store` keeps the same public API (`Add` / `Get` / `List`
  / `Update` / `Delete`) but is now a thin facade over the shared SQLite
  repo; every caller in AiLagoon compiles unchanged.
- **Fail-closed authorization on every mutating handler via
  `melusina-grain-auth`.** Every POST endpoint (`connections/add`,
  `/update`, `/delete`, `/toggle`, `/reconnect`, `claim`, `api/chat`,
  `api/vision`, `routing/save`, `engine-config/save`, `ollama/pull`)
  and every sensitive GET (`connections`, `audit/*`) now enters through
  `requireAuth(ctx, action, perm)` → `grainauth.Require`. The grain
  refuses to start if it cannot construct the authz client; per-request
  denial surfaces as a Sandstorm 403 with a JSON reason. No session-
  cached "isAdmin" shortcut — each request re-checks. A new AST-scan
  gate, `fail_closed_test.go`, fails CI if any future handler is added
  without `requireAuth` or an explicit public allowlist entry, so this
  invariant cannot regress silently.

## v0.6.1 (2026-04-20)

- **Fix stale descriptor injection on /connections.** The v0.6.0
  multi-sidecar refactor switched lagoon.js to a plural
  `AILAGOON_SIDECAR_DESCRIPTORS` map but left `templates/connections.html`
  injecting the old singular `AILAGOON_SIDECAR_DESCRIPTOR` referencing a
  `.SidecarDescriptor` field the handler no longer passes. The
  connections-list page's Grant Access button alerted "Sandstorm HTTP-out
  descriptor is not available on this page" instead of opening the
  address-selector. Template now emits the same plural map
  `new_connection.html` uses and the button forwards the connection's
  stored `SidecarVariant` so the right descriptor is chosen.
- **Silent reconnect before shell round-trip.** New endpoint
  `POST /connections/<id>/reconnect` tries to re-hydrate a disconnected
  connection from the saved sturdyref (or an in-memory live cap) before
  popping the Powerbox dialog. For connections that were granted once
  and later disconnected (grain toggle, restart, or idle release), the
  Grant Access button now reactivates them silently via
  `SandstormApi.Restore` — no shell popup, no user prompt. Only when
  both the in-memory cap and the saved token are gone does the UI fall
  through to a fresh powerboxRequest.

## v0.6.0 (2026-04-15)

- **Multi-sidecar endpoint selector per connection.** Every Add-
  Connection form now shows a five-option picker for which
  ai-lagoon sidecar variant the connection should route through:
  `host`, `remote`, `hypervisor`, `hypervisor.shared`,
  `remote.shared`. Each variant has its own canonical URL
  (ailagoon.sidecar.{variant}) and its own server-built packed
  Cap'n Proto PowerboxDescriptor — the Sandstorm shell opens the
  address-selector popup scoped to exactly the URL the operator
  picked, not a generic fallback.
- **Pre-save reachability probe.** After the Powerbox grant lands
  but BEFORE the claim is persisted onto the Connection record,
  AiLagoon issues a GET through the just-claimed capability to
  confirm the chosen sidecar URL actually answers. Any response
  <500 counts as reachable; on transport error or 5xx the claim
  is released, the connection reverts to the error state, and the
  UI surfaces the failure so the operator can re-pick a different
  variant without clearing dead state.
- `Connection.SidecarVariant` is persisted alongside the Endpoint;
  legacy connections without the field are treated as `host`.

## v0.5.1 (2026-04-15)

- Switch the sidecar host from `ailagoon.sidecar.local` to
  `ailagoon.sidecar.host`. The Sandstorm gateway routes `*.sidecar.host`
  to the out-of-grain sidecar service with a real TLS cert trusted by
  the shell, which fixes the TLS verification error operators saw in
  v0.5.0 when the shell tried to proxy to the `.local` hostname.
  All refs updated in handlers, templates, provider URL defaults, JS,
  Powerbox descriptor, and the description.

## v0.5.0 (2026-04-15)

- **HTTP-out descriptor fix (load-bearing).** The v0.4.1 "corrected
  descriptor" landed as hand-assembled base64 in `static/js/lagoon.js`
  with the Powerbox tag's `value` pointer set to a raw Text instead of
  a `PowerboxTag` STRUCT. The Sandstorm shell's descriptor parser read
  that as garbage and silently fell back to the grain-picker dialog —
  the exact symptom operators reported as "AiLagoon asks for a grain
  permission when it should be asking for URL permission." v0.5.0
  builds the descriptor server-side in `pkg/httpout.BuildHTTPOutDescriptor`
  using the capnp Go library (mirroring finreact-setup's approach),
  injects the packed bytes into the page via a template variable, and
  deletes the hand-assembled JS blobs so the bug cannot regress.
- Apps page now correctly shows the address-selector popup when the
  operator clicks "Request HTTP-out" on a connection.

## v0.4.1 (2026-03-29)

- Fixed Grapple HTTP-out claim flow to restore tokens safely before falling back to `claimRequest()`
- Corrected the canonical HTTP-out Powerbox descriptor for `https://ailagoon.sidecar.host`
- Prepared the reusable AI-Lagoon pearl upgrade for shared Sandstorm testing

## v0.1.0 (2026-02-14)

- Initial release
- Single Pearl type: AI model hub
- Support for Ollama, ChatGPT (OpenAI), and OpenRouter providers
- Explicit per-model connection management
- Grapple HTTP-out for external API access
- Grapple capability offering: ai-text, ai-vision, ai-generic
- Model picker UI for Grapple request sessions
- Built-in chat playground
- Connection persistence across Pearl restarts
