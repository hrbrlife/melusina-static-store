// Package sidecarclasses is the SIGNED sidecar class table: one row per
// production sidecar declaring its class (sidecar_cascade = keyless,
// sidecar_identity = key-bearing) and its key custody.
//
// The table is a separately signed Store document in exactly the style of the
// other signed Store inputs (desiredGenerationMessage, app_catalog pointer):
// a domain-separated, length-prefixed canonical byte message signed with the
// boot-identity operator ed25519 key, carried as a base58 detached signature.
// It is NOT a hand-trusted YAML. Because BOTH the producer (this Store module)
// and the consumer (the deployer's mirrored loader) are Go and the consumer
// re-implements the same canonical bytes with a parity test, there is exactly
// one canonicalization on the wire.
//
// The row set is DERIVED, never hand-listed (G-2): the deployer loader refuses
// a table row naming a component id absent from its own known-component set
// and an enabled sidecar absent from the table — both directions, so the
// table cannot drift from the estate.
//
// The table DECLARES custody; it never fabricates a key. Owner-invented keys
// are forbidden (RUNSTATE 2026-09-24T12:40Z seam audit round 4); actual
// identity enrolment for key-bearing sidecars stays with the existing
// ceremony tooling.
package sidecarclasses

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Schema identifier: a consumer that does not recognize the exact string
// fails closed rather than guessing an older/newer shape.
const Schema = "melusina.sidecar-classes.v1"

// The two sidecar classes. These mirror componentrelease's
// AuthoritySidecarIdentity / AuthoritySidecarCascade constants; the parity
// test in the consumer pins the mirror (G-5 lockstep).
const (
	ClassCascade  = "sidecar_cascade"  // keyless: no SidecarIdentityEntry, no key custody
	ClassIdentity = "sidecar_identity" // key-bearing: the sidecar holds a leased identity
)

// Key custody values.
const (
	CustodyNone                = "none"                  // cascade-only, no keys at the runtime
	CustodySidecarHeldIdentity = "sidecar-held-identity" // the sidecar holds its leased identity keys
)

// sidecarClassesDomain domain-separates this message from every other signed
// Store document (desired-generation, component-release, app-catalog-pointer).
var sidecarClassesDomain = []byte("melusina-sidecar-classes-v1\x00")

// Row is one sidecar's declared class.
type Row struct {
	ID         string `json:"id"`         // sidecar / component id, e.g. "swaprail"
	Class      string `json:"class"`      // sidecar_cascade | sidecar_identity
	KeyCustody string `json:"keyCustody"` // none | sidecar-held-identity
	DeclaredAt string `json:"declaredAt"` // RFC3339 UTC, when the operator declared it
	Source     string `json:"source"`     // provenance, e.g. "registry.go+repos@<sha>" (G-2 record)
}

// Table is the signed document body.
type Table struct {
	Schema            string `json:"schema"`
	StoreID           string `json:"storeId"`        // destination: the consumer pins its own
	OperatorPubkey    string `json:"operatorPubkey"` // base58 ed25519 signer; consumer pins its own authorized key
	SignedAtUnix      int64  `json:"signedAtUnix"`
	Rows              []Row  `json:"rows"`
	OperatorSignature string `json:"operatorSignature"` // base58 detached ed25519 over the canonical message
}

// ContentHash is sha256 over the domain-separated, id-sorted row set. Sorting
// by id means row order is never signable freedom.
func ContentHash(rows []Row) [32]byte {
	sorted := append([]Row(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	message := make([]byte, 0, 64+32*len(sorted))
	message = append(message, sidecarClassesDomain...)
	message = writeU32(message, uint32(len(sorted)))
	for _, row := range sorted {
		digest := rowDigest(row)
		message = append(message, digest[:]...)
	}
	return sha256.Sum256(message)
}

func rowDigest(row Row) [32]byte {
	message := make([]byte, 0, 256)
	message = append(message, sidecarClassesDomain...)
	message = writeLenPrefixed(message, row.ID)
	message = writeLenPrefixed(message, row.Class)
	message = writeLenPrefixed(message, row.KeyCustody)
	message = writeLenPrefixed(message, row.DeclaredAt)
	message = writeLenPrefixed(message, row.Source)
	return sha256.Sum256(message)
}

func message(doc Table, contentHash [32]byte) []byte {
	msg := make([]byte, 0, 256)
	msg = append(msg, sidecarClassesDomain...)
	msg = writeLenPrefixed(msg, doc.Schema)
	msg = writeLenPrefixed(msg, doc.StoreID)
	msg = writeLenPrefixed(msg, doc.OperatorPubkey)
	msg = writeU64(msg, uint64(doc.SignedAtUnix))
	msg = append(msg, contentHash[:]...)
	return msg
}

func writeLenPrefixed(dst []byte, s string) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	dst = append(dst, n[:]...)
	return append(dst, []byte(s)...)
}

func writeU64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}

func writeU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

// Sign canonicalizes the doc (sorts rows, derives OperatorPubkey from the
// operator key) and signs. The caller supplies the boot-identity operator
// private key — the same authority that signs the desired generation.
func Sign(operator *identity.Private, doc Table) (Table, error) {
	if operator == nil {
		return Table{}, errors.New("no operator identity to sign the sidecar class table")
	}
	doc.Schema = Schema
	doc.Rows = sortedRows(doc.Rows)
	if err := doc.validateUnsigned(); err != nil {
		return Table{}, err
	}
	pub, err := operator.Public().SignPublicKey()
	if err != nil {
		return Table{}, fmt.Errorf("operator signing pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return Table{}, errors.New("operator identity has no valid ed25519 signing pubkey")
	}
	doc.OperatorPubkey = primitives.EncodeBase58(pub)
	sig := operator.Sign(message(doc, ContentHash(doc.Rows)))
	if len(sig) != ed25519.SignatureSize {
		return Table{}, fmt.Errorf("operator signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	doc.OperatorSignature = primitives.EncodeBase58(sig)
	return doc, nil
}

// Verify checks the structure, the destination, that OperatorPubkey matches
// the CONSUMER-PINNED authorized key (never a key read from the document),
// and the detached signature. Fail-closed: destination is mandatory.
func Verify(authorized ed25519.PublicKey, expectedStoreID string, doc Table) error {
	if doc.Schema != Schema {
		return fmt.Errorf("sidecar class table schema mismatch: %q", doc.Schema)
	}
	if err := doc.validateUnsigned(); err != nil {
		return err
	}
	// Destination is a MANDATORY fail-closed check: an empty expectedStoreID is
	// a destination bypass, not a wildcard.
	if expectedStoreID == "" {
		return errors.New("expectedStoreID (destination) is required — refusing to verify without a pinned destination")
	}
	if doc.StoreID != expectedStoreID {
		return fmt.Errorf("sidecar class table destination mismatch: doc storeId %q != expected %q", doc.StoreID, expectedStoreID)
	}
	if len(authorized) != ed25519.PublicKeySize {
		return errors.New("authorized operator key is not a valid ed25519 public key")
	}
	authB58 := primitives.EncodeBase58(authorized)
	if doc.OperatorPubkey != authB58 {
		return fmt.Errorf("sidecar class table signer mismatch: doc operator %q != authorized %q (unknown key refused)", doc.OperatorPubkey, authB58)
	}
	sig, err := primitives.DecodeBase58(doc.OperatorSignature)
	if err != nil {
		return fmt.Errorf("decode sidecar class table signature: %w", err)
	}
	if !ed25519.Verify(authorized, message(doc, ContentHash(doc.Rows)), sig) {
		return errors.New("sidecar class table signature invalid")
	}
	return nil
}

func (doc Table) validateUnsigned() error {
	if strings.TrimSpace(doc.StoreID) == "" {
		return errors.New("sidecar class table storeId is required")
	}
	if doc.SignedAtUnix <= 0 {
		return errors.New("sidecar class table signedAtUnix must be positive")
	}
	if len(doc.Rows) == 0 {
		return errors.New("sidecar class table has no rows")
	}
	seen := make(map[string]bool, len(doc.Rows))
	for _, row := range doc.Rows {
		if row.ID == "" || strings.TrimSpace(row.ID) != row.ID {
			return fmt.Errorf("sidecar class table row %q has an invalid id", row.ID)
		}
		if seen[row.ID] {
			return fmt.Errorf("sidecar class table declares sidecar %q more than once", row.ID)
		}
		seen[row.ID] = true
		switch row.Class {
		case ClassCascade:
			if row.KeyCustody != CustodyNone {
				return fmt.Errorf("sidecar class table row %q: a sidecar_cascade (keyless) sidecar holds no keys; keyCustody must be %q", row.ID, CustodyNone)
			}
		case ClassIdentity:
			if row.KeyCustody != CustodySidecarHeldIdentity {
				return fmt.Errorf("sidecar class table row %q: a sidecar_identity (key-bearing) sidecar must declare keyCustody %q", row.ID, CustodySidecarHeldIdentity)
			}
		default:
			return fmt.Errorf("sidecar class table row %q declares unknown class %q (known: sidecar_cascade, sidecar_identity)", row.ID, row.Class)
		}
		if strings.TrimSpace(row.Source) == "" {
			return fmt.Errorf("sidecar class table row %q lacks its derivation source (the G-2 record)", row.ID)
		}
		if strings.TrimSpace(row.DeclaredAt) == "" {
			return fmt.Errorf("sidecar class table row %q lacks declaredAt", row.ID)
		}
	}
	return nil
}

func sortedRows(rows []Row) []Row {
	sorted := append([]Row(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	return sorted
}

// ClassFor returns the declared class for an id. A missing row is the caller's
// refusal (the deployer refuses an enabled sidecar without a row by name; a
// component whose row is absent cannot be resolved fail-open).
func (doc Table) ClassFor(id string) (string, bool) {
	for _, row := range doc.Rows {
		if row.ID == id {
			return row.Class, true
		}
	}
	return "", false
}

// CustodyFor returns the declared key custody for an id.
func (doc Table) CustodyFor(id string) (string, bool) {
	for _, row := range doc.Rows {
		if row.ID == id {
			return row.KeyCustody, true
		}
	}
	return "", false
}

// Count returns the number of rows.
func (doc Table) Count() int { return len(doc.Rows) }

// ContentHashHex returns the canonical content hash as lowercase hex — the
// identity a consumer can pin or log.
func (doc Table) ContentHashHex() string {
	sum := ContentHash(doc.Rows)
	return hex.EncodeToString(sum[:])
}
