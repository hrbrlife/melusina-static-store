ChainWatch is the multi-chain RPC proxy sidecar for cyberteller. It exposes three HTTP endpoints — `GET /api/check/{chain}/{address}`, `POST /api/broadcast`, and `GET /healthz` — and translates each call into the matching JSON-RPC against the configured Ethereum and Solana endpoints.

## Why this is a separate grain

- **Single chokepoint for outbound RPC.** cyberteller never opens a TCP socket to a chain provider; ChainWatch does, and the boundary is auditable in one place.
- **No keys.** ChainWatch holds no signing material. If compromised, the attacker gets RPC URLs — nothing else. cyberteller signs every transaction itself and hands ChainWatch the pre-signed bytes.
- **Stateless.** No DB, no on-disk cache, no scheduler. Restart-safe, replicate-safe.

## Configuration

Set per-deploy via environment (the configurator grain or operator UI):

| Env var       | Default                                          | Purpose                                  |
|---------------|--------------------------------------------------|------------------------------------------|
| `PORT`        | `8091`                                           | HTTP listen port                         |
| `SOL_RPC_URL` | `https://api.devnet.Solana.com`                  | Solana JSON-RPC endpoint                 |
| `ETH_RPC_URL` | `https://ethereum-sepolia-rpc.publicnode.com`    | Ethereum JSON-RPC endpoint               |

Both URLs are required at boot — there is no stub fallback (greenfield posture, fail loud).
