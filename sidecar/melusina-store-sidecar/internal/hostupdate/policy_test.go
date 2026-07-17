package hostupdate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultUpdatePolicyIsSafe(t *testing.T) {
	p := DefaultUpdatePolicy()
	if p.AutoApply {
		t.Fatal("default policy must NOT auto-apply (notify only)")
	}
	if p.PollIntervalSeconds != 300 {
		t.Fatalf("default poll interval = %d, want 300 (5 min)", p.PollIntervalSeconds)
	}
	if p.PromoteDeadlineSeconds != 900 {
		t.Fatalf("default promote deadline = %d, want 900 (<=15 min)", p.PromoteDeadlineSeconds)
	}
	if err := p.validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
}

func TestLoadUpdatePolicyMissingFileIsDefault(t *testing.T) {
	p, err := LoadUpdatePolicy(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("missing policy file should yield default, got: %v", err)
	}
	if p.AutoApply || p.PollIntervalSeconds != 300 {
		t.Fatalf("missing file did not yield safe default: %+v", p)
	}
}

func TestLoadUpdatePolicyPartialEditKeepsDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.json")
	// Admin toggles ONLY autoApply on; timing fields absent -> keep defaults.
	if err := os.WriteFile(p, []byte(`{"schema":"melusina-update-policy-v1","autoApply":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadUpdatePolicy(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !got.AutoApply {
		t.Fatal("autoApply override not applied")
	}
	if got.PollIntervalSeconds != 300 || got.PromoteDeadlineSeconds != 900 || got.DeepStableSeconds != 120 {
		t.Fatalf("absent timing fields did not keep defaults: %+v", got)
	}
}

func TestLoadUpdatePolicyRejectsUnknownField(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(`{"schema":"melusina-update-policy-v1","autoApply":true,"hostAction":"rm -rf"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUpdatePolicy(p); err == nil {
		t.Fatal("LoadUpdatePolicy accepted an unknown field")
	}
}

func TestLoadUpdatePolicyRejectsTrailingData(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(`{"schema":"melusina-update-policy-v1","autoApply":true}`+"\n{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUpdatePolicy(p); err == nil {
		t.Fatal("LoadUpdatePolicy accepted trailing data")
	}
}

func TestUpdatePolicyValidateRejectsDeadlineBelowDeepStable(t *testing.T) {
	p := DefaultUpdatePolicy()
	p.DeepStableSeconds = 1000
	p.PromoteDeadlineSeconds = 500 // deadline < deep-stable
	if err := p.validate(); err == nil {
		t.Fatal("validate accepted a promote deadline shorter than the deep-stable window")
	}
}

func TestLoadUpdatePolicyCoercesZeroTimingToDefault(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(`{"schema":"melusina-update-policy-v1","pollIntervalSeconds":0,"promoteDeadlineSeconds":0}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadUpdatePolicy(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.PollIntervalSeconds != 300 || got.PromoteDeadlineSeconds != 900 {
		t.Fatalf("explicit-zero timing not coerced to default: %+v", got)
	}
}
