# Original Store 1.0.63 publication

This keyless browser service prepares the next original Store runtime release
for the first Bazaar Control admission. It accepts only the reviewed
`bce85bc6b9bd68bf411c047f3a7853684d7830b0` ELF (16,749,761 bytes,
`8fff30321ed863475947e2dac28e05df93bd4bf12fef79423a08f3e0797b77bb`).
The actual Core proposal1985 and original R32 identity adoption must already be
finalized. The retained Store, publisher, license, Master, Core and R32 identities
are unchanged.

The public page at `http://127.0.0.1:18448/` presents three rendered actions:
verify the exact approvals, stage the exact signed artifact request, and publish
the exact signed generation request. The last two call the original Store gates
`POST /publish/installer` and `POST /publish/generation`. There is no signing key,
generic proxy, filesystem publication, chain mutation, host command or install
action in this service. Starting it performs no publication.

Generate the exact unsigned request with `--request-out ABSOLUTE_NEW_FILE`.
The existing `submit-installer --prepare-out` produces the signed multipart
descriptor; `submit-generation --envelope-out` produces its original signed
generation wire body. Both preparations contact no Store. The reviewed artifact
name is `melusina-store-sidecar-1.0.63-8fff30321ed86347.bin`. Keep the generated
files as `artifact-prepared.json` and `generation-prepared.json` in an owned
private inputs directory. They must use the original ARX publisher and exact
original Store public identity. Never put either private signing key in the page
or this service.

Run the compiled service with `--inputs ABSOLUTE_PRIVATE_INPUTS --state
ABSOLUTE_NEW_PRIVATE_JOURNAL --deployer-source ABSOLUTE_ORIGINAL_DEPLOYER`.
The original deployer source must contain the exact reviewed public protocol
assets; every asset is checked against its fixed SHA before the bounded,
read-only Node20/22/24 observer uses it. The observer repeats complete finalized
registry/Core/Master/Store/R32 cascade checks before each outgoing request.

Generation210's signed bytes are retained and independently verified. The
original Store's readiness route verifies its persisted signed generation before
reporting the CAS floor210. This route remains usable after R32 adoption makes
the old advertised Store binary unservable. The request supplies all five
original component records, changing only Store1.0.63 and its actual physical
rollback floor1.0.61/d587. This preserves every unrelated component and rollback
floor. Store rechecks each supplied component against its chain and artifact
before producing generation211. The page independently verifies the original
operator signature, complete resulting cohort and exact returned raw hash.

Before either network write, the exact prepared body and an append-only uncertain
intent are durably retained. A repeated action or uncertain outcome refuses.
No automatic resend is provided. Network ambiguity needs independent original
Store readback and review; it cannot be converted into a success receipt.
Browser reload reads the existing process journal. A new process cannot reuse or
overwrite the original journal directory.

The downloaded receipt proves only gated artifact/generation publication.
The original controller must still apply the runtime and prove physical bytes
and deep stability. First Bazaar Core publication, Store-only installation,
actual first-grain command-key export and subsequent policy/grants are separate.
Synthetic HTTP tests confer none of those authorities.
