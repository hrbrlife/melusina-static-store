package artifactvault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSidecarVaultFacadeExposesOnlySharedDescriptorsAndUnixClient(t *testing.T) {
	descriptor := DescriptorFor([]byte("final candidate"))
	if descriptor.SHA256 == "" || descriptor.Bytes != int64(len("final candidate")) {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	raw, err := os.ReadFile(filepath.Join("vault.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"type Vault =", "Open = shared.Open"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("sidecar vault facade must not expose a direct disk vault: %q", forbidden)
		}
	}
}
