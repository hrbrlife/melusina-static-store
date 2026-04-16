**fineract Setup** is the Sandstorm companion wizard for `fineract-sidecar`.

It provisions the attached Apache Fineract backend, walks the operator
through the bootstrap workflow, and exports a signed trust bundle shared by
both security gates:

- Gate 1: the Go HTTPS sidecar
- Gate 2: the Java `SolanaSignatureAuthenticationFilter` inside Fineract

The wizard packages the cold-start work that has to happen before ccash can
talk to a hardened Fineract install: tenant setup, offices, currencies, chart
of accounts, savings products, signer registration, governance policy, and
trust-bundle export.
