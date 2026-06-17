package apphash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// refAppHash is an INDEPENDENT re-implementation of the apphash contract, used
// only to cross-check Compute. Keeping a second code path means a refactor that
// silently breaks the production fold is caught here, not only by the hardcoded
// golden constants below.
func refAppHash(files [][2][]byte) string {
	// caller passes already-sorted {relPath, bytes} pairs.
	outer := sha256.New()
	for _, f := range files {
		inner := sha256.New()
		inner.Write([]byte("F "))
		inner.Write(f[0])
		inner.Write([]byte{0})
		inner.Write(f[1])
		outer.Write(inner.Sum(nil))
	}
	return hex.EncodeToString(outer.Sum(nil))
}

// TestCanonical_Golden pins Canonical to golden vectors computed from the
// documented algorithm (the same algorithm proven against a real catalog app's
// on-chain appHash during the #25 diagnosis). A drift in the fold (prefix,
// separator, order, or hash) changes these constants.
func TestCanonical_Golden(t *testing.T) {
	cases := []struct {
		name string
		spk  []byte
		meta []byte
		want string
	}{
		{
			name: "canonical_pair",
			spk:  []byte("spk-bytes-A"),
			meta: []byte(`{"name":"x"}`),
			want: "b7b4415ebec5bd548debe0e029f764bffd94737a276a5dfdcf38ca8882928334",
		},
		{
			name: "empty_metadata",
			spk:  []byte("spk-bytes-A"),
			meta: []byte(""),
			want: "5ef12ce63f9fdaf0e44d65b79793054f06027fbd0a71c5d8d2d3a788d1373dab",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonical(bytes.NewReader(tc.spk), tc.meta)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("Canonical = %s, want golden %s", got, tc.want)
			}
			ref := refAppHash([][2][]byte{
				{[]byte(SPKName), tc.spk},
				{[]byte(MetadataName), tc.meta},
			})
			if got != ref {
				t.Fatalf("Canonical = %s, independent ref = %s", got, ref)
			}
		})
	}
}

// TestCanonical_NotSpkSha256 is the crux of bug #25: the canonical app-hash is the
// TREE-hash and must NOT equal sha256(spk) — the old (wrong) serve/publish model.
func TestCanonical_NotSpkSha256(t *testing.T) {
	spk := []byte("sandstorm package bytes — deterministic test SPK content v1")
	meta := []byte(`{"appTitle":"Test","appVersion":"1.0.0"}`)
	got, err := Canonical(bytes.NewReader(spk), meta)
	if err != nil {
		t.Fatal(err)
	}
	spkSum := sha256.Sum256(spk)
	if got == hex.EncodeToString(spkSum[:]) {
		t.Fatal("Canonical must NOT equal sha256(spk) (that is the #25 bug)")
	}
}

// TestCompute_SortInvariant proves Compute sorts by rel path, so input order does
// not change the result (matching apphash.Compute, which sorts).
func TestCompute_SortInvariant(t *testing.T) {
	a := []byte("alpha")
	b := []byte("beta")
	inOrder, err := Compute([]File{
		{RelPath: "app.spk", R: bytes.NewReader(a)},
		{RelPath: "metadata.json", R: bytes.NewReader(b)},
	})
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := Compute([]File{
		{RelPath: "metadata.json", R: bytes.NewReader(b)},
		{RelPath: "app.spk", R: bytes.NewReader(a)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if inOrder != reversed {
		t.Fatalf("Compute not sort-invariant: %s != %s", inOrder, reversed)
	}
}

// TestCanonical_MetadataBinds proves the metadata.json bytes are bound into the
// hash: two SPKs identical but for one metadata byte differ. This is what makes a
// swapped/drifted metadata.json fail the serve+publish gate.
func TestCanonical_MetadataBinds(t *testing.T) {
	spk := []byte("same spk")
	h1, _ := Canonical(bytes.NewReader(spk), []byte(`{"v":1}`))
	h2, _ := Canonical(bytes.NewReader(spk), []byte(`{"v":2}`))
	if h1 == h2 {
		t.Fatal("metadata change must change the app-hash")
	}
}
