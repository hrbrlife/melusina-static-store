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
pearl via Grapple.
