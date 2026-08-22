package artifactvault

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestVaultStoresAndLoadsOnlyExactDescriptor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	vault, err := Open(root, 1024)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := vault.Store(context.Background(), []byte("trusted candidate"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := vault.Store(context.Background(), []byte("trusted candidate"))
	if err != nil || second != descriptor {
		t.Fatalf("repeat store = %#v err=%v", second, err)
	}
	body, err := vault.Load(context.Background(), descriptor)
	if err != nil || string(body) != "trusted candidate" {
		t.Fatalf("load = %q err=%v", body, err)
	}
	wrongSize := descriptor
	wrongSize.Bytes++
	if _, err := vault.Load(context.Background(), wrongSize); err == nil {
		t.Fatal("load accepted a matching digest with a different byte count")
	}
}

func TestSeparateVaultProcessesStoreTheSameObjectIdempotently(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	first, err := Open(root, 1024)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(root, 1024)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		descriptor Descriptor
		err        error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	var wait sync.WaitGroup
	for _, vault := range []*Vault{first, second} {
		wait.Add(1)
		go func(vault *Vault) {
			defer wait.Done()
			<-start
			descriptor, err := vault.Store(context.Background(), []byte("trusted candidate"))
			results <- outcome{descriptor: descriptor, err: err}
		}(vault)
	}
	close(start)
	wait.Wait()
	close(results)
	var descriptors []Descriptor
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent store: %v", result.err)
		}
		descriptors = append(descriptors, result.descriptor)
	}
	if len(descriptors) != 2 || descriptors[0] != descriptors[1] {
		t.Fatalf("concurrent descriptors = %#v", descriptors)
	}
}

func TestVaultRefusesTamperAndSymlinkObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	vault, err := Open(root, 1024)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := vault.Store(context.Background(), []byte("trusted candidate"))
	if err != nil {
		t.Fatal(err)
	}
	path, err := vault.path(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered artifact"), fileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Load(context.Background(), descriptor); err == nil {
		t.Fatal("tampered artifact was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "other")
	if err := os.WriteFile(other, []byte("trusted candidate"), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Load(context.Background(), descriptor); err == nil {
		t.Fatal("symlinked artifact was accepted")
	}
}

func TestVaultRefusesSharedRootAndOversizedObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, 16); err == nil {
		t.Fatal("shared vault root was accepted")
	}
	if err := os.Chmod(root, directoryMode); err != nil {
		t.Fatal(err)
	}
	vault, err := Open(root, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Store(context.Background(), []byte("four")); err == nil {
		t.Fatal("oversized object was accepted")
	}
	if _, err := vault.Load(context.Background(), Descriptor{SHA256: "not-a-digest", Bytes: 1}); err == nil {
		t.Fatal("malformed descriptor was accepted")
	}
	if _, err := vault.Load(context.Background(), Descriptor{}); err == nil {
		t.Fatal("empty descriptor was accepted")
	}
}
