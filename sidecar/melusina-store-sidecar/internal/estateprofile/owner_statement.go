package estateprofile

// RequireFoundationCharter compares a charter-bound owner document against the
// independently reviewed charter digest before any foundation effect. The
// binding is fail-closed: a document that names no charter and a document that
// names a different one are the same refusal, because neither is the charter
// the caller reviewed.
func RequireFoundationCharter(value FoundationAuthorizationV1, charterSHA256 string) error {
	if value.EstateCharterSHA256 == "" || value.EstateCharterSHA256 != charterSHA256 {
		return refuse(RefusalCharterDigestMismatch)
	}
	return nil
}
