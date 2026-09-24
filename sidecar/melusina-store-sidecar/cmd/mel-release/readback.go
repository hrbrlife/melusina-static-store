package main

// ReleaseEntry readback: the whole of approve's register step.
//
// mel-release approve registers no entry and approves or executes no
// register proposal. The owner-authorized runner registers the release's
// ReleaseEntry through the master NFT custodian's vault, one governed vault
// transaction per entry (spec R5); approve then reads that account back and
// admits it before it lets anything be promoted:
//
//   - the account at the ReleaseEntry PDA derived from the estate's master
//     mint and the frozen app_hash, owned by the estate's license registry;
//   - decoded with the program's exact layout (internal/releaseentry);
//   - admitted for exactly the frozen release (app_hash, app_id, release_hash,
//     version), under the estate's master mint and release custodian, and
//     signed by a publisher the owners enrolled in the profile's releaseTrust
//     (the program verified the signature; the estate decides whose it may
//     be).
//
// A missing, foreign, malformed, recalled or differently-attested entry is
// refused by name and leaves the WAL where it was. The same readback runs
// again immediately before every promote (promoteAdmitted: approve's promote
// and repair-catalog's re-projection), so an entry recalled, changed or no
// longer trusted after the first run is never promoted.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
)

// readbackReceiptName is where approve records the admitted account.
const readbackReceiptName = "release-entry-readback.json"

// errFinalReleaseUnbound names a finalized RELEASE.json that does not carry
// the admitted entry's facts; errReleaseEntryChanged an entry whose account
// bytes differ from the ones approve recorded although it is still admitted.
var (
	errFinalReleaseUnbound = errors.New("final-release-not-bound-to-release-entry")
	errReleaseEntryChanged = errors.New("release-entry-changed-since-readback")
)

// releaseEntryTrust projects the bound estate onto the admission rule: the
// profile's master mint, the release custodian the Store checks served
// releases against (roles.store-release's vault) and releaseTrust.
func releaseEntryTrust(c Config) (*releaseentry.Trust, error) {
	master, err := base58Key(c.MasterNftMint)
	if err != nil {
		return nil, fmt.Errorf("%w: anchors.masterMint: %v", releaseentry.ErrTrustUnconfigured, err)
	}
	custodian, err := base58Key(c.SquadsVault)
	if err != nil {
		return nil, fmt.Errorf("%w: release custodian vault: %v", releaseentry.ErrTrustUnconfigured, err)
	}
	keys := make([][32]byte, 0, len(c.ReleasePublisherKeys))
	for _, encoded := range c.ReleasePublisherKeys {
		if !isLowerHex(encoded, 64) {
			return nil, fmt.Errorf("%w: releaseTrust.publisherKeys holds %q", releaseentry.ErrTrustUnconfigured, encoded)
		}
		raw, _ := hex.DecodeString(encoded)
		keys = append(keys, [32]byte(raw))
	}
	return releaseentry.NewTrust(master, custodian, keys, c.ReleasePublisherThreshold)
}

func base58Key(value string) ([32]byte, error) {
	if value == "" {
		return [32]byte{}, errors.New("not bound")
	}
	key, err := pda.FromBase58(value)
	if err != nil {
		return [32]byte{}, err
	}
	return [32]byte(key), nil
}

func hex32(value, name string) ([32]byte, error) {
	if !isLowerHex(value, 64) {
		return [32]byte{}, fmt.Errorf("%s must be 64 lowercase hex characters", name)
	}
	raw, _ := hex.DecodeString(value)
	return [32]byte(raw), nil
}

// readbackReleaseEntry reads the frozen release's ReleaseEntry and admits it.
// It returns the entry and the exact account bytes it admitted.
func readbackReleaseEntry(c Config, prov SignerProvider, rec *walReceipt) (releaseentry.Entry, []byte, error) {
	derived, err := deriveReleasePDA(c.MasterNftMint, rec.NewAppHash, c.ProgramID)
	if err != nil {
		return releaseentry.Entry{}, nil, fmt.Errorf("derive ReleaseEntry PDA: %w", err)
	}
	if derived != rec.NewReleasePDA {
		return releaseentry.Entry{}, nil, fmt.Errorf("the WAL's ReleaseEntry %s is not the PDA %s the estate's master mint and registry derive for app_hash %s", rec.NewReleasePDA, derived, rec.NewAppHash)
	}
	trust, err := releaseEntryTrust(c)
	if err != nil {
		return releaseentry.Entry{}, nil, err
	}
	want := releaseentry.Expectation{AppID: releaseentry.AppIDHash(rec.AppID), Version: rec.Version}
	if want.AppHash, err = hex32(rec.NewAppHash, "WAL appHash"); err != nil {
		return releaseentry.Entry{}, nil, err
	}
	if want.ReleaseHash, err = hex32(rec.ReleaseHash, "WAL releaseHash"); err != nil {
		return releaseentry.Entry{}, nil, err
	}
	account, err := prov.ReleaseEntryAccount(derived)
	if err != nil {
		return releaseentry.Entry{}, nil, fmt.Errorf("read ReleaseEntry %s: %w", derived, err)
	}
	if !account.Present {
		return releaseentry.Entry{}, nil, fmt.Errorf("%w: no ReleaseEntry at %s for app %s version %s; approve does not register it or execute a register proposal. "+
			"The owner-authorized runner registers it; re-run approve once it is on chain", releaseentry.ErrMissing, derived, rec.AppID, rec.Version)
	}
	if account.Owner != c.ProgramID {
		return releaseentry.Entry{}, nil, fmt.Errorf("%w: account %s is owned by %s, not the estate's license registry %s", releaseentry.ErrOwnerMismatch, derived, account.Owner, c.ProgramID)
	}
	entry, err := releaseentry.Decode(account.Data)
	if err != nil {
		return releaseentry.Entry{}, nil, err
	}
	if err := trust.Admit(entry, want); err != nil {
		return releaseentry.Entry{}, nil, err
	}
	return entry, account.Data, nil
}

// newReadbackReceipt records the admitted account. It has no timestamp: the
// same account always yields the same bytes.
func newReadbackReceipt(c Config, rec *walReceipt, entry releaseentry.Entry, account []byte) readbackReceipt {
	return readbackReceipt{
		Schema:                 readbackSchema,
		AppID:                  rec.AppID,
		ReleaseEntryPDA:        rec.NewReleasePDA,
		ProgramID:              c.ProgramID,
		AccountSHA256:          sha256Hex(account),
		AccountSize:            len(account),
		MasterNftMint:          pda.ToBase58(entry.MasterNFTMint[:]),
		AppHash:                hex.EncodeToString(entry.AppHash[:]),
		AppIDHash:              hex.EncodeToString(entry.AppID[:]),
		ReleaseHash:            hex.EncodeToString(entry.ReleaseHash[:]),
		Version:                entry.Version,
		PublisherSquadsVault:   pda.ToBase58(entry.PublisherSquadsVault[:]),
		PublisherEd25519Pubkey: hex.EncodeToString(entry.PublisherEd25519Pubkey[:]),
		Signature:              hex.EncodeToString(entry.Signature[:]),
		SignedPayloadHash:      hex.EncodeToString(entry.SignedPayloadHash[:]),
		RegisteredBy:           pda.ToBase58(entry.RegisteredBy[:]),
		RegisteredAt:           entry.RegisteredAt,
		Status:                 entry.Status.String(),
		PublisherThreshold:     c.ReleasePublisherThreshold,
	}
}

// writeReadbackReceipt writes receipt and reads it back as the WAL's release:
// a receipt that names another PDA or release hash is refused, not recorded.
func writeReadbackReceipt(path string, rec *walReceipt, receipt readbackReceipt) (artifactRef, error) {
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return artifactRef{}, err
	}
	if err := writeDurable(path, append(raw, '\n')); err != nil {
		return artifactRef{}, err
	}
	_, ref, err := readReadbackReceipt(path, rec.NewReleasePDA, rec.ReleaseHash)
	return ref, err
}

// attestedFinalRelease is the finalized RELEASE.json's chain-bound part.
type attestedFinalRelease struct {
	ReleaseEntryPDA    string `json:"releaseEntryPda"`
	SignedAtUnix       int64  `json:"signedAtUnix"`
	MasterNftMint      string `json:"masterNftMint"`
	LicenseSquadsVault string `json:"licenseSquadsVault"`
	AuthorSig          string `json:"authorSig"`
	QuorumPolicy       struct {
		Threshold   int    `json:"threshold"`
		MemberCount int    `json:"memberCount"`
		MultisigPda string `json:"multisigPda"`
	} `json:"quorumPolicy"`
}

// readAttestedFinalRelease reads the provider's finalized RELEASE.json and
// requires it to carry exactly the admitted entry: the release binding
// readFinalReleaseJSON checks (the WAL's appHash, version and nonce), the
// entry's own app_hash, release_hash and version, the release PDA, master
// mint, custodian vault, the entry's signature as authorSig, its
// registered_at as signedAtUnix, and the estate's release quorum. Promote
// submits these bytes to the Store; nothing the admitted entry does not say
// may reach it.
func readAttestedFinalRelease(path string, c Config, rec *walReceipt, entry releaseentry.Entry) (artifactRef, error) {
	final, ref, err := readFinalReleaseJSON(path, rec.NewAppHash, rec.Version, rec.ReleaseNonce)
	if err != nil {
		return artifactRef{}, err
	}
	var rel attestedFinalRelease
	if _, err := readNativeJSON(path, &rel); err != nil {
		return artifactRef{}, err
	}
	for _, field := range []struct {
		name      string
		got, want any
	}{
		{"appHash", final.AppHash, hex.EncodeToString(entry.AppHash[:])},
		{"releaseHash", final.ReleaseHash, hex.EncodeToString(entry.ReleaseHash[:])},
		{"version", final.Version, entry.Version},
		{"releaseEntryPda", rel.ReleaseEntryPDA, rec.NewReleasePDA},
		{"masterNftMint", rel.MasterNftMint, pda.ToBase58(entry.MasterNFTMint[:])},
		{"licenseSquadsVault", rel.LicenseSquadsVault, pda.ToBase58(entry.PublisherSquadsVault[:])},
		{"signedAtUnix", rel.SignedAtUnix, entry.RegisteredAt},
		{"authorSig", rel.AuthorSig, base64.StdEncoding.EncodeToString(entry.Signature[:])},
		{"quorumPolicy.multisigPda", rel.QuorumPolicy.MultisigPda, c.SquadsMultisig},
		{"quorumPolicy.threshold", rel.QuorumPolicy.Threshold, c.SquadsThreshold},
		{"quorumPolicy.memberCount", rel.QuorumPolicy.MemberCount, c.SquadsMemberCount},
	} {
		if field.got != field.want {
			return artifactRef{}, fmt.Errorf("%w:%s: finalized RELEASE.json has %v, the admitted ReleaseEntry and estate say %v", errFinalReleaseUnbound, field.name, field.got, field.want)
		}
	}
	return ref, nil
}

// registerByReadback is the POSED -> REGISTERED step: read back and admit the
// runner-registered entry, record it, then have the provider bind its
// candidate RELEASE.json to it and check the result field by field.
func registerByReadback(c Config, prov SignerProvider, rec *walReceipt) error {
	entry, account, err := readbackReleaseEntry(c, prov, rec)
	if err != nil {
		return err
	}
	ref, err := writeReadbackReceipt(c.receiptPath(rec.AppID, readbackReceiptName), rec, newReadbackReceipt(c, rec, entry, account))
	if err != nil {
		return fmt.Errorf("record ReleaseEntry readback: %w", err)
	}
	finalReleasePath := c.receiptPath(rec.AppID, "final-release.json")
	if err := prov.FinalizeRelease(rec.AppID, rec.NewAppHash, rec.ReleaseHash, rec.Version, rec.ReleaseNonce, finalReleasePath); err != nil {
		return err
	}
	finalRef, err := readAttestedFinalRelease(finalReleasePath, c, rec, entry)
	if err != nil {
		return err
	}
	rec.RegisterReceipt = ref
	rec.ReleaseJSON = finalRef
	return verifyRegisteredLive(prov, rec)
}

// errPromoteNotAdmitted names a promote the shared admission refused. It wraps
// the admission's own refusal (release-entry-recalled,
// release-entry-publisher-untrusted, release-entry-changed-since-readback, ...),
// so a caller sees both which gate stopped it and why.
var errPromoteNotAdmitted = errors.New("promote-refused-release-entry-not-admitted")

// promoteAdmitted is the one entry point to SignerProvider.Promote. Every
// promote path goes through it: approve's promote at REGISTERED and
// repair-catalog's re-projection of a terminal release. It runs
// admitForPromote immediately before the Store promote and promotes nothing
// the admission refuses. TestEveryPromoteGoesThroughTheSharedAdmission fails
// by name if any other function in this package calls Promote.
func promoteAdmitted(c Config, prov SignerProvider, app App, rec *walReceipt, receiptOut string) error {
	if err := admitForPromote(c, prov, rec); err != nil {
		return err
	}
	return prov.Promote(app, rec.NewAppHash, rec.ReleaseHash, rec.Version, rec.StageID, receiptOut)
}

// admitForPromote is the Go ReleaseEntry admission every promote path runs
// immediately before promote, and the check a resumed promote passes before
// the WAL records it. It reads the account back again rather than trusting an
// earlier run or the provider's status projection:
//
//   - the readback receipt approve recorded still binds the WAL's release;
//   - the entry is still admitted (owner, layout, Active with no revocation
//     time, the frozen bindings, the estate's master mint and custodian, a
//     releaseTrust publisher and a verifying signature): a recall since the
//     last run is refused as release-entry-recalled;
//   - its account bytes are the ones the readback receipt recorded; and
//   - the finalized RELEASE.json is unchanged and still binds it.
//
// Every refusal is wrapped in errPromoteNotAdmitted.
func admitForPromote(c Config, prov SignerProvider, rec *walReceipt) error {
	if err := admitRecordedReleaseEntry(c, prov, rec); err != nil {
		return fmt.Errorf("%w: ReleaseEntry %s: %w", errPromoteNotAdmitted, rec.NewReleasePDA, err)
	}
	return nil
}

func admitRecordedReleaseEntry(c Config, prov SignerProvider, rec *walReceipt) error {
	if err := verifyArtifactRef(rec.RegisterReceipt); err != nil {
		return fmt.Errorf("ReleaseEntry readback receipt: %w", err)
	}
	recorded, _, err := readReadbackReceipt(rec.RegisterReceipt.Path, rec.NewReleasePDA, rec.ReleaseHash)
	if err != nil {
		return err
	}
	entry, account, err := readbackReleaseEntry(c, prov, rec)
	if err != nil {
		return err
	}
	if got := sha256Hex(account); got != recorded.AccountSHA256 {
		return fmt.Errorf("%w: ReleaseEntry %s account sha256 is %s; approve recorded %s", errReleaseEntryChanged, rec.NewReleasePDA, got, recorded.AccountSHA256)
	}
	if err := verifyArtifactRef(rec.ReleaseJSON); err != nil {
		return fmt.Errorf("finalized RELEASE.json: %w", err)
	}
	if _, err := readAttestedFinalRelease(rec.ReleaseJSON.Path, c, rec, entry); err != nil {
		return err
	}
	return nil
}
