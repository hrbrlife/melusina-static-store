// Command genparity emits cross-repo parity vectors for the sidecar class
// table: a signed table (both classes) plus the canonical content hash, so the
// deployer's mirrored loader can be pinned to the Store's exact canonical
// bytes. Run from the store module root:
//
//	go run ./internal/sidecarclasses/genparity > vectors.json
//
// Every identity value below is a DETERMINISTIC REHEARSAL placeholder derived
// in-process (ed25519 keys expanded to base58) — the retiring estate's
// program ids, domains and store id are never embedded, so the tool compiles
// clean under the retiring-estate source and built-byte scans. These vectors
// never touch a chain.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/sidecarclasses"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// vectorKey derives the deterministic key the vector contract pins (the
// deployer's parity test re-derives the signing seed itself).
func vectorKey(b byte) ed25519.PrivateKey {
	var seed [32]byte
	for i := range seed {
		seed[i] = b + byte(i)
	}
	return ed25519.NewKeyFromSeed(seed[:])
}

// vectorAddress expands a deterministic key into the base58 pubkey address
// the identity Ref fields carry — a real curve point, invented here, never
// copied from any estate.
func vectorAddress(b byte) string {
	pub := vectorKey(b).Public().(ed25519.PublicKey)
	return primitives.EncodeBase58(pub)
}

func main() {
	ref := identity.Ref{
		// No retiring-estate literal: the vector's chain reference is a
		// deterministic rehearsal stand-in, never a real network name
		// (census scans in both build flavors pass).
		Kind: identity.KindSidecar, ChainID: "rehearsal:parity",
		ProgramID: vectorAddress(0xC0),
		// Deterministic stand-in addresses for vector generation ONLY —
		// these vectors never touch a chain.
		LicenseMint: vectorAddress(0xD0),
		Domain:      "genparity.rehearsal.invalid", PDA: "11111111111111111111111111111111",
		SidecarID: "parity", KeyVersion: 1,
	}
	op, err := identity.NewPrivate(ref, [32]byte(vectorKey(0xA0)), [32]byte(vectorKey(0xB0)))
	if err != nil {
		panic(err)
	}
	pub, err := op.Public().SignPublicKey()
	if err != nil {
		panic(err)
	}
	doc, err := sidecarclasses.Sign(op, sidecarclasses.Table{
		StoreID:      "genparity-rehearsal-store",
		SignedAtUnix: 1789000000,
		Rows: []sidecarclasses.Row{
			{ID: "mermail", Class: sidecarclasses.ClassCascade, KeyCustody: sidecarclasses.CustodyNone, DeclaredAt: "2026-09-27T00:00:00Z", Source: "registry.go@0c695588+chaingate.go:262"},
			// swap-rail's boot gate reads no SidecarIdentityEntry (the
			// b01 read-only repo census), so its row is CASCADE/none. The
			// identity row the deployer's older vectors carried was a
			// fixture convenience, not a derivation.
			{ID: "swaprail", Class: sidecarclasses.ClassCascade, KeyCustody: sidecarclasses.CustodyNone, DeclaredAt: "2026-09-27T00:00:00Z", Source: "registry.go@0c695588+repos:no-sidecaridentityentry-read"},
		},
	})
	if err != nil {
		panic(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	out := map[string]string{
		// The exact signed document bytes and the DETACHED signature over them.
		"docJson":      string(raw),
		"signatureB58": doc.OperatorSignature,
		"pubkeyB58":    doc.OperatorPubkey,
		"pubkeyRawB64": base64.StdEncoding.EncodeToString(pub),
		"contentHash":  doc.ContentHashHex(),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, "parity vectors written")
}
