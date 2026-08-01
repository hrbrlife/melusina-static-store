package componentrelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path/filepath"
	"testing"
)

func TestBinaryReplaceStageKeepsDifferentGenerationArtifactsSeparate(t *testing.T) {
	work := t.TempDir()
	first := []byte("first signed artifact")
	second := []byte("second signed artifact")
	firstSum := sha256.Sum256(first)
	secondSum := sha256.Sum256(second)
	a := NewBinaryReplaceAdapter(func(_ context.Context, rawURL string) (io.ReadCloser, error) {
		if rawURL == "https://origin/first" {
			return io.NopCloser(bytes.NewReader(first)), nil
		}
		return io.NopCloser(bytes.NewReader(second)), nil
	})
	install := ComponentInstall{ComponentID: "rrs-store"}
	one, err := a.Stage(context.Background(), ComponentRelease{
		ComponentID: "rrs-store", BundleURL: "https://origin/first",
		SHA256: hex.EncodeToString(firstSum[:]), SizeBytes: int64(len(first)),
	}, install, work)
	if err != nil {
		t.Fatalf("stage first: %v", err)
	}
	two, err := a.Stage(context.Background(), ComponentRelease{
		ComponentID: "rrs-store", BundleURL: "https://origin/second",
		SHA256: hex.EncodeToString(secondSum[:]), SizeBytes: int64(len(second)),
	}, install, work)
	if err != nil {
		t.Fatalf("stage second: %v", err)
	}
	if one.Path == two.Path {
		t.Fatalf("different signed artifacts reused staging path %q", one.Path)
	}
	if got, want := filepath.Base(one.Path), "rrs-store."+hex.EncodeToString(firstSum[:])[:16]+".staged"; got != want {
		t.Fatalf("first staging name %q, want %q", got, want)
	}
}
