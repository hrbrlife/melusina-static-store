TeleScreen is the Sandstorm-side screening sidecar plus admin core grain for the Melusina constellation.

It exposes compact sanctions, adverse-media, compliance, and blockchain-risk APIs through Sandstorm, with signed configuration, grant validation, and grain-scoped isolation.

A complete install is three Sandstorm grains that compose across two SPKs: the REST/JSON sidecar and the HTMX admin + member core grain (both in this SPK), plus the setup grain shipped separately as `telescreen-companion.spk`. Setup signs the trust bundle; core consumes it; sidecar verifies and serves.

Packaging is `spk dev` / `spk pack`. Docker and direct system service deployment are not part of the polished MVP path.
