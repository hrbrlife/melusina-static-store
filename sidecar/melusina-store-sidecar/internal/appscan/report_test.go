package appscan

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestScanReportSubsecondSkewBounded(t *testing.T) {
	now := time.Date(2026, 10, 13, 17, 0, 0, 100000000, time.UTC)
	spk, metadata, release, runtime := []byte("spk"), []byte("metadata"), []byte("release"), []byte("runtime")
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	key := hex.EncodeToString(private.Public().(ed25519.PublicKey))
	makeReport := func(stamp time.Time) Report {
		report := Report{Schema: Schema, Method: "POST", Target: "/publish", SPKSHA256: Hash(spk), MetadataSHA256: Hash(metadata), ReleaseSHA256: Hash(release), RuntimeContractSHA256: Hash(runtime), ScannedAtUnix: stamp.Unix(), ScannedAt: stamp.Format("2006-01-02T15:04:05.000000000Z07:00"), ScannerVersion: "fixture", DatabaseVersion: "fixture", Clean: true}
		if err := report.Sign(private); err != nil {
			t.Fatal(err)
		}
		return report
	}
	verify := func(report Report) error {
		return Verify(report, key, "POST", "/publish", spk, metadata, release, runtime, now)
	}
	if err := verify(makeReport(now.Add(1500 * time.Millisecond))); err != nil {
		t.Fatalf("SCAN_REPORT_SMALL_FUTURE_SKEW_REFUSED: %v", err)
	}
	if err := verify(makeReport(now.Add(2*time.Second + time.Nanosecond))); err == nil || err.Error() != "scan-report-expired" {
		t.Fatalf("SCAN_REPORT_LARGE_FUTURE_SKEW_ADMITTED: %v", err)
	}
	legacy := makeReport(now.Add(1500 * time.Millisecond))
	legacy.ScannedAt = ""
	if err := legacy.Sign(private); err != nil {
		t.Fatal(err)
	}
	if err := verify(legacy); err != nil {
		t.Fatalf("SCAN_REPORT_SIGNED_LEGACY_SECOND_REFUSED: %v", err)
	}
	changed := makeReport(now)
	changed.ScannedAtUnix++
	if err := changed.Sign(private); err == nil || !strings.Contains(err.Error(), "timestamp-invalid") {
		t.Fatalf("SCAN_REPORT_SUBSECOND_UNIX_MISMATCH_ADMITTED: %v", err)
	}
	foreignZone := makeReport(now)
	foreignZone.ScannedAt = now.In(time.FixedZone("plus-one", 3600)).Format(time.RFC3339Nano)
	if err := foreignZone.Sign(private); err == nil || !strings.Contains(err.Error(), "timestamp-invalid") {
		t.Fatalf("SCAN_REPORT_NON_UTC_TIMESTAMP_ADMITTED: %v", err)
	}
}
