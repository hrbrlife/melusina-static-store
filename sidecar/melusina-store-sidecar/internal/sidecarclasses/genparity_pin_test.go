package sidecarclasses

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestGenparityOutputIsPinned (round-2 MINOR, lockstep): the Store now carries
// its own committed copy of the cross-repo parity vector, and this test pins
// genparity's exact output to it. A Store-side change to the canonical message
// (ContentHash, rowDigest, message) fails HERE first — previously it passed
// every Store test and was only caught if someone regenerated into the
// deployer.
//
// The pinned vector is the byte-exact stdout of
// go run ./internal/sidecarclasses/genparity (deterministic; verified 3×
// byte-identical in the rework evidence). When the encoder legitimately
// changes, regenerate BOTH this file and the deployer's
// deploy-ui/internal/sidecarclasses/parity_vectors.json in one lockstep
// landing (they must stay byte-identical to each other).
func TestGenparityOutputIsPinned(t *testing.T) {
	if testing.Short() {
		t.Skip("genparity pin runs the generator")
	}
	// The test binary runs with its package dir as cwd; genparity is the
	// genparity/ subpackage of this package's directory.
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = "genparity"
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run genparity: %v", err)
	}
	pinned, err := os.ReadFile("parity_vectors.json")
	if err != nil {
		t.Fatalf("read the committed parity vector: %v (commit genparity's stdout as internal/sidecarclasses/parity_vectors.json)", err)
	}
	if strings.TrimSpace(string(out)) != strings.TrimSpace(string(pinned)) {
		t.Fatalf("genparity output drifted from the committed parity_vectors.json — regenerate BOTH this file and the deployer's deploy-ui/internal/sidecarclasses/parity_vectors.json in one lockstep landing")
	}
	// The pinned vector must itself be a coherent signed document: the
	// signature verifies against the pinned key over the pinned document.
	var v map[string]string
	if err := json.Unmarshal(pinned, &v); err != nil {
		t.Fatalf("the committed vector is not the generator's JSON: %v", err)
	}
	var doc Table
	if err := json.Unmarshal([]byte(v["docJson"]), &doc); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(v["pubkeyRawB64"])
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, "genparity-rehearsal-store", doc); err != nil {
		t.Fatalf("the committed vector's own signature does not verify: %v", err)
	}
	if doc.ContentHashHex() != v["contentHash"] {
		t.Fatal("the committed vector's contentHash does not match its document")
	}
}
