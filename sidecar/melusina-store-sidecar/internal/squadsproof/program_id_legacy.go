//go:build !estatebootstrap

package squadsproof

// DefaultProgramIDBase58 is @sqds/multisig v2.1.4's deployed v4 program id.
// It is retained only for legacy Store builds. Estate-bootstrap builds must
// obtain the program id from the enrolled estate profile instead.
const DefaultProgramIDBase58 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"

// DefaultProgramID is the decoded legacy program id.
var DefaultProgramID = mustDecodePubkey(DefaultProgramIDBase58)
