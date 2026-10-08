package releaseevidence

import "testing"

func TestPublicCoreVerifierRequiresIndependentServiceTrust(t *testing.T) {
	for _, config := range []Config{{}, {RPCURL: "https://example.invalid"}, {RPCURL: "http://example.invalid"}, {RPCURL: "https://example.invalid/?authority=caller"}} {
		if _, err := NewCoreVerifier(config); err == nil {
			t.Fatal("incomplete or caller-selected Core trust accepted")
		}
	}
	var unavailable *CoreVerifier
	if _, err := unavailable.VerifySelectedRelease(t.Context(), "", "", "", nil); err == nil {
		t.Fatal("unavailable verifier returned authority")
	}
	if _, err := DecodeReleaseDescriptor([]byte(`{"sourceBaselineAuthenticated":true}`)); err == nil {
		t.Fatal("public decoder accepted asserted source authority")
	}
}
