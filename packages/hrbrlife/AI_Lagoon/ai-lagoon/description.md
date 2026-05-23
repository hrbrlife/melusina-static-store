# AiLagoon

The AI model hub pearl for Melusina. Register multiple LLM providers,
manage per-model connections, and expose AI capabilities to other
pearls via Grapple — all behind a single Sandstorm HTTP-out permission
to the ai-lagoon sidecar.

## Providers

- **Ollama** — local or remote Ollama server, any model it can host
- **ChatGPT** — OpenAI-compatible API (GPT-4o, 4.1, o1, o3, 4.5, 4.6)
- **OpenRouter** — 100+ models from Anthropic, Google, Meta, Mistral,
  DeepSeek, and more through a single proxy

## Grapple capabilities published by this pearl

Other pearls can request AI from AiLagoon via Grapple:

- `ai-text` — generic text / chat completion
- `ai-vision` — image understanding and OCR
- `ai-generic` — consumer picks a model in the Grapple UI at grant time
- Direct per-model — scoped to one provider + model, useful when a
  consumer wants a specific capability class (e.g. reasoning)

## How HTTP-out works

All providers route through `https://ailagoon.sidecar.host`; the
sidecar's path prefix (`/{provider}/{apiKey}/...`) demultiplexes per
provider. At grain startup AiLagoon asks Sandstorm for a single
HTTP-out permission to that host — the shell renders the
address-selector popup (not the grain picker), and the operator grants
or denies the host once. Connections persist across pearl restarts via
`SandstormApi.save()` / `restore()`.

## Playground

A built-in chat playground lets you test any connected model without
leaving the pearl — useful for validating credentials, checking
capabilities, or prototyping prompts before calling them from another
pearl via Grapple. Every assistant reply renders a **provenance card**
underneath the bubble: ISO-8601 UTC timestamp, request-ID (cross-
referenceable in `/audit`), provider+connection name, and a
sealed/cleartext pill so compliance officers can attribute and time-
stamp every output without leaving the chat.

## Transcript anchoring — roadmap, not shipped

AiLagoon does **not** currently anchor inference transcripts on-chain.
Earlier catalog copy described "Solana-pinned inference transcripts"
as a shipped feature; that was overclaim. As of v0.7.11 the only
on-chain artifact AiLagoon participates in is the **publish-side**
ReleaseEntry that signs this SPK manifest itself (program
`7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb`, PDA in the catalog
`attest` block). Per-conversation transcript pinning to the user's
Squads-controlled wallet is on the v0.8 roadmap; until then,
transcripts live append-only in the grain's encrypted SQLite store
and surface in the audit log as metadata only (no prompt/response
content retained, by design — see `pkg/audit/logger.go`).
