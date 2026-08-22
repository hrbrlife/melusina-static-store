package artifactvault

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSidecarVaultFacadeUsesTheSharedDescriptorAndStore(t *testing.T) {
	vault, err := Open(filepath.Join(t.TempDir(), "vault"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := vault.Store(context.Background(), []byte("final candidate"))
	if err != nil || descriptor != DescriptorFor([]byte("final candidate")) {
		t.Fatalf("store = %#v err=%v", descriptor, err)
	}
}
