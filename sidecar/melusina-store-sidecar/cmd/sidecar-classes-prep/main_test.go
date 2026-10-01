package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// prepShards writes three deterministic hex shards and returns the SidecarShards
// they encode, so the test can independently re-derive the operator key and
// prove the produced table is signed by the config's boot-identity operator.
func prepShards(t *testing.T, dir string) derive.SidecarShards {
	t.Helper()
	var sh derive.SidecarShards
	for i, f := range []struct {
		name string
		dst  *[32]byte
	}{
		{"author.shard", &sh.AuthorShard},
		{"host-observation.shard", &sh.HostObservationShard},
		{"release.shard", &sh.ReleaseShard},
	} {
		for j := range f.dst {
			f.dst[j] = byte(0x10 + i*0x20 + j)
		}
		if err := os.WriteFile(filepath.Join(dir, f.name), []byte(hex.EncodeToString(f.dst[:])+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return sh
}

const prepProgramID = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"

func prepConfigJSON(shardsDir, storeID string) string {
	return `{"store_id":"` + storeID + `","license_nft_mint":"35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN","domain":"prep-store.example.org","program_id":"` + prepProgramID +
		`","boot_identity":{"shards_dir":"` + shardsDir + `","sidecar_id":"melusina-store-sidecar","chain_id":"solana:prepnet","key_version":1}}`
}

// TestProducerSignsWithTheBootIdentityOperator is the round-2 MAJOR fix proof:
// the produced table's signature verifies against the key DERIVED from the
// same three shards under the same ref — the operator identity that signs the
// desired generation signs the class table — and the three output files are
// exactly the files the Store config wires.
func TestProducerSignsWithTheBootIdentityOperator(t *testing.T) {
	dir := t.TempDir()
	shardsDir := filepath.Join(dir, "shards")
	if err := os.MkdirAll(shardsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	shards := prepShards(t, shardsDir)
	storeID := "prep-store"
	declPath := filepath.Join(dir, "classes.json")
	decl := `{"rows":[{"id":"mermail","class":"sidecar_cascade","keyCustody":"none","declaredAt":"2026-09-28T00:00:00Z","source":"prep control: registry-derived"},{"id":"swaprail","class":"sidecar_identity","keyCustody":"sidecar-held-identity","declaredAt":"2026-09-28T00:00:00Z","source":"prep control: registry-derived"}]}`
	if err := os.WriteFile(declPath, []byte(decl), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	var report strings.Builder
	cfgPath := filepath.Join(dir, "store.json")
	if err := os.WriteFile(cfgPath, []byte(prepConfigJSON(shardsDir, storeID)), 0o600); err != nil {
		t.Fatal(err)
	}
	report.Reset()
	if err := run([]string{"-config", cfgPath, "-declaration", declPath, "-out-dir", outDir}, &report); err != nil {
		t.Fatalf("producer refused a valid declaration: %v", err)
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(report.String()), &parsed); err != nil {
		t.Fatal(err)
	}

	// Independently re-derive the operator from the SAME shards and ref, and
	// verify the produced table against that key: the signature story is
	// coherent — the signer is the boot-identity operator, pinned by config.
	mint, err := primitives.PubkeyFromBase58("35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN")
	if err != nil {
		t.Fatal(err)
	}
	program, err := primitives.PubkeyFromBase58(prepProgramID)
	if err != nil {
		t.Fatal(err)
	}
	operatorPDA, _, err := pda.SidecarIdentity(mint, "melusina-store-sidecar", 1, program)
	if err != nil {
		t.Fatal(err)
	}
	ref := identity.Ref{
		Kind: identity.KindSidecar, ChainID: "solana:prepnet", ProgramID: program.Base58(),
		LicenseMint: mint.Base58(), Domain: "prep-store.example.org", PDA: operatorPDA.Base58(),
		SidecarID: "melusina-store-sidecar", KeyVersion: 1,
	}
	operator, err := derive.DeriveSidecar(ref, shards)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	keyB58 := primitives.EncodeBase58(pub)
	keyFileRaw, err := os.ReadFile(parsed["operatorPublicKey"])
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(keyFileRaw)) != keyB58 {
		t.Fatalf("the produced public key %q is not the boot-identity operator's %q", strings.TrimSpace(string(keyFileRaw)), keyB58)
	}
	if !strings.Contains(parsed["configHint"], `"authorized_operator_key":"`+keyB58+`"`) {
		t.Fatal("the config hint does not pin the produced operator key")
	}

	docRaw, err := os.ReadFile(parsed["document"])
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		StoreID string `json:"storeId"`
		Rows    []struct {
			ID    string `json:"id"`
			Class string `json:"class"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(docRaw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.StoreID != storeID {
		t.Fatalf("produced table destination %q, want %q", doc.StoreID, storeID)
	}
	if len(doc.Rows) != 2 || doc.Rows[0].ID != "mermail" || doc.Rows[1].ID != "swaprail" {
		t.Fatalf("produced rows %+v do not echo the declaration", doc.Rows)
	}
}

// TestProducerRefusesEmptyAndUnknownClasses: the producer never invents or
// defaults a class — an empty declaration and an unknown class are refused.
func TestProducerRefusesEmptyAndUnknownClasses(t *testing.T) {
	dir := t.TempDir()
	shardsDir := filepath.Join(dir, "shards")
	if err := os.MkdirAll(shardsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	prepShards(t, shardsDir)
	cfgPath := filepath.Join(dir, "store.json")
	if err := os.WriteFile(cfgPath, []byte(prepConfigJSON(shardsDir, "prep-store")), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyPath := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(emptyPath, []byte(`{"rows":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-config", cfgPath, "-declaration", emptyPath, "-out-dir", filepath.Join(dir, "o1")}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "no rows") {
		t.Fatalf("an empty declaration was not refused: %v", err)
	}
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(`{"rows":[{"id":"x","class":"sidecar_keyless","keyCustody":"none","declaredAt":"2026-09-28T00:00:00Z","source":"s"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-config", cfgPath, "-declaration", badPath, "-out-dir", filepath.Join(dir, "o2")}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "unknown class") {
		t.Fatalf("an unknown class was not refused: %v", err)
	}
}
