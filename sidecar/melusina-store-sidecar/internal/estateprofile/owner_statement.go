package estateprofile

import "errors"

// RequireFoundationCharter compares a charter-bound owner document against the
// independently reviewed charter digest before any foundation effect. D50
// supplies the verifier; this fail-closed declaration is a test reachability
// seam because no such API exists at the contract base.
func RequireFoundationCharter(_ FoundationAuthorizationV1, _ string) error {
	return errors.New("D50_UNIMPLEMENTED")
}
