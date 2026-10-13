package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Reviewer negatives (C2-REVIEW-TX CXT-005): each pending-marker check must
// refuse by name on its own, with the installer digest matching the changed
// bytes so the digest pin cannot mask the check under test.
func TestPendingMarkerChecksRefuseIndependentlyOfDigest(t *testing.T) {
	estate, profile := strings.Repeat("a", 64), strings.Repeat("b", 64)
	marker := func(schema, install, tenant, estateID, profileSHA string) string {
		return `{"schema":"` + schema + `","installId":"` + install + `","tenantId":"` + tenant +
			`","estateId":"` + estateID + `","estateProfileSha256":"` + profileSHA + `"}`
	}
	load := func(raw string) error {
		path := filepath.Join(t.TempDir(), "pins.json")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(raw))
		return loadPendingRoster(path, hex.EncodeToString(sum[:]))
	}
	if err := load(marker(pendingRosterSchema, "install-a", "tenant-a", estate, profile)); err != nil {
		t.Fatalf("PENDING_MARKER_POSITIVE_REFUSED: %v", err)
	}
	for name, raw := range map[string]string{
		"PENDING_MARKER_FOREIGN_SCHEMA_ACCEPTED":  marker("melusina.evidence-pack-roster.v1", "install-a", "tenant-a", estate, profile),
		"PENDING_MARKER_TENANT_CHARSET_ACCEPTED":  marker(pendingRosterSchema, "install-a", "Tenant/A", estate, profile),
		"PENDING_MARKER_NON_HEX_ESTATE_ACCEPTED":  marker(pendingRosterSchema, "install-a", "tenant-a", strings.Repeat("z", 64), profile),
		"PENDING_MARKER_NON_HEX_PROFILE_ACCEPTED": marker(pendingRosterSchema, "install-a", "tenant-a", estate, strings.Repeat("g", 64)),
		"PENDING_MARKER_INSTALL_CHARSET_ACCEPTED": marker(pendingRosterSchema, "install A", "tenant-a", estate, profile),
		"PENDING_MARKER_UNKNOWN_FIELD_ACCEPTED":   strings.TrimSuffix(marker(pendingRosterSchema, "install-a", "tenant-a", estate, profile), "}") + `,"keys":{}}`,
		"PENDING_MARKER_NOT_CANONICAL_ACCEPTED":   strings.Replace(marker(pendingRosterSchema, "install-a", "tenant-a", estate, profile), `","tenantId"`, `", "tenantId"`, 1),
		"PENDING_MARKER_TRAILING_VALUE_ACCEPTED":  marker(pendingRosterSchema, "install-a", "tenant-a", estate, profile) + "{}",
	} {
		if err := load(raw); err == nil {
			t.Fatal(name)
		}
	}
}
