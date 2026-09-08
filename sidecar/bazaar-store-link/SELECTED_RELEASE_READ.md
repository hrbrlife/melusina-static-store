# Held Store selected-release evidence

`GET /v1/selected-releases/{appId}` is a fixed read through the already held
Store Link. It forwards only to the connector's configured, mutually pinned
mTLS Store origin at `GET /control/v1/selected-releases/{appId}`. The app ID is
exactly 52 lowercase alphanumeric characters. Queries, suffix paths and other
methods are refused. Caller headers never become private Store authority.
The Store route is absent from both public router modes.

The `bazaar-control-selected-release-snapshot-v1` response names the configured
Store, app, immutable generation and observation time. Its `indexBytes`,
`pointerBytes`, `metadataBytes`, `releaseBytes`, `runtimeContractBytes` and
`spkBytes` fields are standard-base64 encodings of the **original bytes** read
from one immutable generation. No JSON artifact is rewritten or re-signed.
The runtime field is null only for a release that does not require a runtime
contract. SPK is bounded to 64 MiB; each of the five public JSON artifacts is
bounded to 1 MiB. Only this successful fixed read has the matching base64
response allowance. Ordinary control responses and credentials keep their
existing narrow limits.

The Store verifies its independently configured operator's catalog pointer,
exact index selection, serving domain, package ID, canonical app hash,
metadata identity and runtime binding. It freshly checks the active per-app
ReleaseEntry with the configured complete Squads authority, exact app/version/
registration time/PDA, blacklist and StoreReleaseListing. No cached verdict or
empty-Store-authority compatibility path is used. Missing pointers and revoked
or unavailable authority fail closed; the read creates no catalog state.

For a browser `POST /v1/build-jobs`, the connector first validates the unchanged
64 KiB source-intent schema and exact configured Store ID. It obtains the
selected readout itself, then constructs the private
`bazaar-control-trusted-build-submission-v1` envelope: original
`sourceIntentBytes` plus the `selectedRelease` object. Only the fixed private
worker `POST /v1/build-submissions` accepts this envelope. The browser cannot
call that route or provide evidence, a baseline or an endpoint. Existing exact
job polling remains `GET /v1/build-jobs/{id}`. The larger internal body bound is
the selected-read response plus one bounded encoded source intent and framing;
public artifact byte fields acquire no additional base64 expansion.

This response is a **locator and public evidence transport**, not a source
attestation. It contains no source commit, authenticated-baseline flag, new
signer or publication authorization. The production build worker still needs
to independently verify the original per-app finalized
chain/Core and SPK signatures, and reproduce the selected package's ELF and
package definition under its pinned keyless historical build environment.
An unsigned local commit crosswalk can locate a candidate source only. A
historical test-suite failure remains distinct from binary reproduction.

Deployment composition remains the existing held Pearl Store Link, connector
mTLS identity, private Store listener, configured chain reader and immutable
catalog generation. This source increment adds no public publication path and
does not deploy or grant any of those capabilities.
