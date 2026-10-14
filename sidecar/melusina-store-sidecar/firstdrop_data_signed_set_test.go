package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFirstDropDataReleaseRequiresExactSignedRole(t *testing.T) {
	for _, role := range []string{"offline-sign-runtime", "opensanctions-index", "msb-index"} {
		t.Run(role, func(t *testing.T) {
			const digest = "1d2da7270c8b628f8c885315a369b09c1612699a0a51eae0156b8f2e78dba1ea"
			name := role + ".tar.xz"
			var set servedReleaseSet
			if err := json.Unmarshal([]byte(`{"artifacts":[{"role":"`+role+`","name":"`+name+`","sha256":"`+digest+`","sizeBytes":4096}]}`), &set); err != nil {
				t.Fatal(err)
			}
			if err := requireSignedSetArtifact(set, "data", name, digest, 4096); err != nil {
				t.Fatalf("FIRSTDROP_DATA_SIGNED_MEMBER_REFUSED: %v", err)
			}
			set.Artifacts[0].Role = "foreign-" + role
			if err := requireSignedSetArtifact(set, "data", name, digest, 4096); err == nil || !strings.Contains(err.Error(), "release-set-artifact-absent") {
				t.Fatalf("FIRSTDROP_FOREIGN_DATA_ROLE_ACCEPTED: %v", err)
			}
		})
	}
}
