// Command genparity emits cross-repo parity vectors for the sidecar class
// table: a signed table (both classes) plus the canonical content hash, so the
// deployer's mirrored loader can be pinned to the Store's exact canonical
// bytes. Run from the store module root:
//
//	go run ./internal/sidecarclasses/genparity > vectors.json
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/sidecarclasses"
)

func main() {
	var signSeed, boxSeed [32]byte
	for i := range signSeed {
		signSeed[i] = byte(0xA0 + i)
		boxSeed[i] = byte(0xB0 + i)
	}
	ref := identity.Ref{
		Kind: identity.KindSidecar, ChainID: "solana:devnet",
		ProgramID: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
		// Deterministic stand-in 32-byte base58 mint for vector generation
		// ONLY — these vectors never touch a chain.
		LicenseMint: "So11111111111111111111111111111111111111112",
		Domain:      "bazaar.melusina-os.org", PDA: "11111111111111111111111111111111",
		SidecarID: "parity", KeyVersion: 1,
	}
	op, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		panic(err)
	}
	pub, err := op.Public().SignPublicKey()
	if err != nil {
		panic(err)
	}
	doc, err := sidecarclasses.Sign(op, sidecarclasses.Table{
		StoreID:      "melusina-os-root-store",
		SignedAtUnix: 1789000000,
		Rows: []sidecarclasses.Row{
			{ID: "mermail", Class: sidecarclasses.ClassCascade, KeyCustody: sidecarclasses.CustodyNone, DeclaredAt: "2026-09-27T00:00:00Z", Source: "registry.go@0c695588+chaingate.go:262"},
			{ID: "swaprail", Class: sidecarclasses.ClassIdentity, KeyCustody: sidecarclasses.CustodySidecarHeldIdentit, DeclaredAt: "2026-09-27T00:00:00Z", Source: "registry.go@0c695588+repos"},
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
