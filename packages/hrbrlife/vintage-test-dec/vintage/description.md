Vintage Remote Desktop gives every Melusina operator a disposable, full Linux desktop rendered in the browser. Pearls start in sandbox mode — every change is ephemeral and wiped when the pearl closes. Click Save to upgrade the pearl to a persistent, Solana-backed workspace.

## Why Vintage

- **Pinned session snapshots** — cryptographically anchor any desktop session to your Solana wallet; snapshots are tamper-evident, citable across Pearls via Grapple, and recoverable if the session crashes
- **Ephemeral-first sandbox** — by default, everything is temporary; persistence is an explicit choice, not a default; ideal for one-off work that shouldn't pollute your environment
- **Wallet-rooted persistent state** — when you click Save, session state is anchored to your Solana wallet; ownership and restoration tied to your key; no operator backdoor

## Ideal For

- One-off tooling that you don't want polluting your main environment
- Demo environments that reset cleanly
- Remote-ops consoles where persistence should be an explicit choice, not a default
- Isolated testing and experimentation

## Features

- **Full Linux desktop** — apt, gcc, git, Python, Node, Docker, and standard utilities
- **Browser-based** — no VNC client, no RDP software; open in any browser
- **File transfer** — drag-drop files into the desktop; export files back out
- **Clipboard sync** — paste between your computer and the remote desktop
- **Audio** — WebRTC audio support for VoIP and media playback
- **Offline-capable** — all assets bundled; no external calls

## Status

*Shipped v1.0.0.* Browser-based Linux desktop with ephemeral sandbox default, Solana-pinned session snapshots, full-featured toolchain.
