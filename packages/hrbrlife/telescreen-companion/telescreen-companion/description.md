# Telescreen Configuration

This Sandstorm grain is the operator-facing configuration UI for the
**telescreen sidecar** (pr_ninja). It lets you set every knob the
sidecar exposes — secrets, platform toggles, LLM tunables, crawl
parameters, storage paths, search providers, product context — entirely
through the browser, with no SSH-into-container required.

The grain stores its configuration inside its own Sandstorm sandbox
(`/var`) and pushes the merged config to the live sidecar via an
authenticated HTTP-out capability claimed once through the Powerbox.
Secrets never touch the sidecar's disk: the sidecar holds them in
process memory, where they are flushed on restart.

This is an admin-only grain. Non-admin users see a read-only landing
page explaining that they need the `admin` permission.
