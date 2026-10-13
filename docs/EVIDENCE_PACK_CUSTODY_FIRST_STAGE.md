# Evidence Pack custody first-stage release

The first custody release is roster-pending. It has no app public keys and
starts the custody executable with `-roster-pending`, so every custody request
is refused until a later owner-attested rostered successor is installed.

From the Store source checkout, build the two binaries from its sidecar module:

```sh
cd sidecar/melusina-store-sidecar
go build -o "$PRIVATE_BUILD/melusina-store-sidecar" .
go build -o "$PRIVATE_BUILD/evidence-pack-custody" ./cmd/evidence-pack-custody
cd ../..
```

Read `INSTALL_ID` and `TENANT_ID` from the approved install spec's
`metadata.installId` and `metadata.verticalInstanceId`. Read `PROFILE_SHA256`
from the Store verifier's successful `estate-profile-review` of the exact
owner-signed profile. The publisher reviews those three values with the
approved plan before signing the release. The guest separately compares the
installed marker with its signed install selection, so a release for another
install or tenant cannot be the first-stage selection.

```sh
python3 scripts/build-evidence-pack-custody-bundle.py \
  --stage first \
  --binary "$PRIVATE_BUILD/evidence-pack-custody" \
  --install-id "$INSTALL_ID" --tenant-id "$TENANT_ID" \
  --estate-profile "$SIGNED_ESTATE_PROFILE" \
  --estate-profile-sha256 "$PROFILE_SHA256" \
  --estate-verifier "$PRIVATE_BUILD/melusina-store-sidecar" \
  --output "$PRIVATE_BUILD/evidence-pack-custody-first.tar"

python3 scripts/build-evidence-pack-custody-bundle.py \
  --verify-built --stage first \
  --install-id "$INSTALL_ID" --tenant-id "$TENANT_ID" \
  --estate-profile "$SIGNED_ESTATE_PROFILE" \
  --estate-profile-sha256 "$PROFILE_SHA256" \
  --estate-verifier "$PRIVATE_BUILD/melusina-store-sidecar" \
  --output "$PRIVATE_BUILD/evidence-pack-custody-first.tar"
```

The two commands print the same SHA-256. The readback checks the complete
canonical tar, exact pending marker, three allowed members, and inert runtime
contract. It refuses an unsigned profile, a foreign install or tenant, an app
key, a rostered tar, or hidden trailing bytes. The immutable tar is then staged
through the same governed sidecar path as the other v8 releases:

```sh
cd sidecar/melusina-store-sidecar
go run ./cmd/submit-installer \
  --store "$SIGNED_STORE_URL" --class sidecar \
  --name "$IMMUTABLE_CUSTODY_RELEASE_NAME" \
  --artifact "$PRIVATE_BUILD/evidence-pack-custody-first.tar" \
  --publisher-key "$ENROLLED_PUBLISHER_KEY_FILE" \
  --store-pubkey "$STORE_OPERATOR_PUBLIC_KEY_FILE" \
  --store-id "$SIGNED_STORE_ID" --store-domain "$SIGNED_STORE_DOMAIN" \
  --license-mint "$SIGNED_STORE_LICENSE_MINT" \
  --program-id "$SIGNED_LICENSE_REGISTRY_PROGRAM" \
  --verified-slot "$VERIFIED_CHAIN_SLOT" \
  --connect-address "$PRIVATE_STORE_INGRESS" \
  --store-tls-leaf "$PINNED_STORE_LEAF_PEM"
```

Keep the Store's staged receipt and its artifact digest. The release becomes a
selectable, served sidecar only after the existing signed sidecar class table,
chain approvals, and `submit-generation` promotion/readback. Do not replace a
previously staged name with different bytes. The install selects this exact
Store-attested first release; the final selected grains then create their own
keys, and the owner-attested rostered successor follows the existing roster
producer and strictly-forward custody transition.

For that successor, run the same builder with `--stage rostered --pins
<owner-attested-pins> --roster-request <selected-grain-readback-request>
--roster-attestation <owner-attestation>`, plus the signed profile and verifier.
Its `--verify-built --stage rostered` readback also requires `--roster-request`.
