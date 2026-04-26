AiLagoon is the AI model hub pearl for Melusina. Register multiple LLM providers, manage per-model connections, and expose AI capabilities to other pearls via Grapple — all behind a single Melusina HTTP-out permission to the ai-lagoon sidecar.

## Why AiLagoon

- **Pinned inference transcripts** — cryptographically anchor any model conversation to your Solana wallet; transcripts are tamper-evident, citable across Pearls via Grapple, and verifiable independent of the operator
- **Single HTTP-out permission** — one security boundary; all provider traffic routes through the sidecar; you grant access once, revoke anytime
- **Wallet-rooted Grapple capability routing** — consuming Pearls request AI capabilities via Grapple; routing is scoped to the requesting Pearl; no cross-Pearl data leakage

## Supported Providers

- **Ollama** — local or remote Ollama server, any model it can host
- **OpenAI** — ChatGPT API (GPT-4o, 4-Turbo, o1, o3, 4.5, 4.6, newer models)
- **OpenRouter** — 100+ models from Anthropic, Google, Meta, Mistral, DeepSeek, and more through a single proxy

## Published Grapple Capabilities

Other Pearls request AI from AiLagoon via Grapple:

- `ai-text` — generic text / chat completion
- `ai-vision` — image understanding and OCR
- `ai-generic` — consumer picks a model in the Grapple UI at grant time
- Direct per-model — scoped to one provider + model; useful when a consumer wants a specific capability class (e.g., reasoning)

## Playground

A built-in chat playground lets you test any connected model without leaving the pearl — useful for validating credentials, checking capabilities, or prototyping prompts before calling them from another Pearl via Grapple.

## Status

*Shipped v0.7.0.* Production-ready AI model hub with Ollama, ChatGPT, OpenRouter; Solana-pinned inference transcripts.
