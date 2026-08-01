package componentrelease

import "testing"

// TestBinaryReplaceAdapterWiring guards the integration point (constructor,
// Kind, RegisterAdapter/AdapterFor) in the regular suite. The full adversarial
// lifecycle (Stage/Verify/Apply/Probe/Rollback, all 5 HOLD reqs) is exercised by
// the verifier's sidecar_adapter_probe.py overlay, which is green against this
// integrated source.
func TestBinaryReplaceAdapterWiring(t *testing.T) {
	a := NewBinaryReplaceAdapter(nil)
	if a.Kind() != ApplyBinaryReplace {
		t.Fatalf("Kind() = %q, want %q", a.Kind(), ApplyBinaryReplace)
	}
	// Isolated registration check (reset the process-local table around it so we
	// do not pollute other tests).
	adapters = map[string]Adapter{}
	if err := RegisterAdapter(a); err != nil {
		t.Fatalf("RegisterAdapter: %v", err)
	}
	got, ok := AdapterFor(ApplyBinaryReplace)
	if !ok || got.Kind() != ApplyBinaryReplace {
		t.Fatal("AdapterFor(binary-replace) not found after RegisterAdapter")
	}
	// A second registration for the same kind is refused (no silent replace).
	if err := RegisterAdapter(NewBinaryReplaceAdapter(nil)); err == nil {
		t.Fatal("duplicate RegisterAdapter accepted")
	}
	adapters = map[string]Adapter{}
}
