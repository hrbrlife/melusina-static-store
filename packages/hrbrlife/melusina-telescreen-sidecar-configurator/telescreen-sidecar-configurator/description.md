# TeleScreen Sidecar Configurator

This Sandstorm pearl is the operator-facing configuration UI for the
**TeleScreen sidecar**. It lets you set every knob the
sidecar exposes — secrets, platform toggles, AiLagoon routing, crawl
parameters, storage paths, search providers, product context — entirely
through the browser, with no SSH-into-container required.

The pearl stores its configuration inside its own Sandstorm sandbox
(`/var`) and pushes the merged config to the live sidecar via an
authenticated HTTP-out capability claimed once through the Grapple.
Secrets never touch the sidecar's disk: the sidecar holds them in
process memory, where they are flushed on restart.

This is an admin-only grain. Non-admin users see a read-only landing
page explaining that they need the `admin` permission.

Scope lock: this app is configuration-only and advertises no Cap'n Proto
capabilities. The separate TeleScreen Hub app owns team screening history,
Vintage/AiLagoon/sidecar claims, and the consumer-facing screening service.
