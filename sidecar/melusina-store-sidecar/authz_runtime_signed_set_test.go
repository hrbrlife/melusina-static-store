package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The guest authz runtime is a data-class InstallerReleaseEntry. The Store
// serves it only when the highest publisher-signed estate set names the exact
// authz-runtime role, basename, digest and size.
func TestAuthzRuntimeDataRequiresExactSignedMember(t *testing.T) {
	const hash = "1d2da7270c8b628f8c885315a369b09c1612699a0a51eae0156b8f2e78dba1ea"
	const name = "melusina-authzsign-runtime.tar"
	var set servedReleaseSet
	if err := json.Unmarshal([]byte(`{"artifacts":[{"role":"authz-runtime","name":"`+name+`","sha256":"`+hash+`","sizeBytes":24637440}]}`), &set); err != nil {
		t.Fatal(err)
	}
	if err := requireSignedSetArtifact(set, "data", name, hash, 24637440); err != nil {
		t.Fatalf("AUTHZ_RUNTIME_SIGNED_MEMBER_REFUSED: %v", err)
	}
	for _, mutation := range []struct {
		name, role, digest string
		size               int64
		want               string
	}{
		{"foreign-role", "sidecar", hash, 24637440, "release-set-artifact-absent"},
		{"foreign-digest", "authz-runtime", strings.Repeat("0", 64), 24637440, "release-set-artifact-mismatch"},
		{"foreign-size", "authz-runtime", hash, 24637441, "release-set-artifact-mismatch"},
	} {
		changed := set
		changed.Artifacts = append(changed.Artifacts[:0:0], set.Artifacts...)
		changed.Artifacts[0].Role = mutation.role
		changed.Artifacts[0].SHA256 = mutation.digest
		changed.Artifacts[0].SizeBytes = mutation.size
		if err := requireSignedSetArtifact(changed, "data", name, hash, 24637440); err == nil || !strings.Contains(err.Error(), mutation.want) {
			t.Fatalf("AUTHZ_RUNTIME_%s_NOT_REFUSED: want %s, got %v", mutation.name, mutation.want, err)
		}
	}
}
