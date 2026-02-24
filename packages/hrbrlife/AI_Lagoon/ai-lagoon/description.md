# AI Lagoon

**Your AI workspace. Your server. Your conversations.**

AI Lagoon is a self-hosted AI collaboration and exploration platform for Melusina. Each conversation lives in its own **Pearl** — a sealed, per-document container with its own database, permissions, and sharing rules. No conversation can see another unless you explicitly connect them via **Grapple**.

---

## 🧠 How It Works

Create a new Pearl to start a conversation. Each Pearl is an isolated AI session — your prompts, responses, and context stay inside that container. Share a Pearl with collaborators to let them participate in the same conversation thread without exposing your other sessions.

### Key Features

- **Per-Pearl Isolation** — Every AI conversation runs in its own sealed container with separate storage and permissions
- **Multi-Model Support** — Connect to local LLMs (Ollama), OpenAI-compatible endpoints, or other AI providers
- **Collaboration** — Share a Pearl to let others join a conversation with role-based access
- **Grapple Connections** — Link AI Pearls to other app Pearls to provide context — feed documents, spreadsheets, or code into your AI session
- **Privacy-First** — All prompts and responses stay on your server. No third-party telemetry. No data harvesting
- **Offline Capable** — Works air-gapped with local models — no internet required

---

## 🔐 Security Model

| Role | Capabilities |
|---|---|
| 👁️ **Viewer** | Read conversation history |
| ✏️ **Editor** | Send prompts and interact with the AI |
| 👑 **Admin** | Configure model endpoints, manage access |

> Each Pearl enforces permissions server-side. The server rejects unauthorized requests regardless of what the client sends. Your AI conversations are as private as your Sandstorm server.

---

## 💰 Pricing

**Free.** Install and use on your own server. No subscription, no usage limits, no telemetry.
