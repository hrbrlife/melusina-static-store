package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/installerpublish"
)

// A member above the Store's /publish/installer member ceiling is refused by
// name before it is read or signed: nothing is written and nothing is
// contacted. A sparse file stands in for the oversized member, so the
// refusal must come from the size, not from reading it.
func TestOversizedMemberRefusedBeforeSigning(t *testing.T) {
	f := newEnvelopeOutFixture(t)
	var stdout bytes.Buffer
	if err := run(f.args("--timeout", "58m"), &stdout); err != nil {
		t.Fatalf("INSTALLER_MEMBER_CEILING_POSITIVE_CONTROL: a small member at the 58m timeout was refused: %v", err)
	}
	f.envelopePath = f.envelopePath + ".oversized"
	if err := os.Truncate(f.artifactPath, installerpublish.MaxArtifactBytes+1); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	err := run(f.args("--timeout", "58m"), &stdout)
	if err == nil || !strings.HasPrefix(err.Error(), refuseArtifactSize+":") {
		t.Fatalf("INSTALLER_OVERSIZED_MEMBER_SIGNED: %v", err)
	}
	if _, statErr := os.Stat(f.envelopePath); !os.IsNotExist(statErr) || stdout.Len() != 0 || f.contacted {
		t.Fatal("INSTALLER_OVERSIZED_MEMBER_LEFT_EFFECTS: an envelope was written, reported or sent")
	}
}
