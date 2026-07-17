package hostupdate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

const updatePolicySchema = "melusina-update-policy-v1"

// maxPolicyBytes bounds the shell-writable policy file (small typed JSON).
const maxPolicyBytes = 1 << 20

// UpdatePolicy is the OPERATOR-preference half of the controller's config: the
// check cadence, whether verified updates auto-apply or only notify, and the
// health-timing windows. It is deliberately SHELL-WRITABLE (the admin panel
// toggles auto-apply / frequency), so — unlike the root-owned component-registry
// allowlist — it is NOT a security trust root: it only decides WHETHER to apply,
// never WHAT (the artifact hash, chain gate, and component allowlist are enforced
// by the controller regardless of this file). A missing file yields the SAFE
// default (auto-apply OFF, 5-minute poll).
type UpdatePolicy struct {
	Schema string `json:"schema"`
	// AutoApply OFF (default) => the controller checks + verifies + stages + posts
	// a pending-update notification, but does NOT mutate the host. ON => it applies.
	AutoApply bool `json:"autoApply"`
	// PollIntervalSeconds is the check cadence (card default: 5 minutes).
	PollIntervalSeconds int64 `json:"pollIntervalSeconds"`
	// DeepStableSeconds is how long a component must stay target+healthy after
	// restart before the apply is committed terminal (the WAL's deep-stable window).
	DeepStableSeconds int64 `json:"deepStableSeconds"`
	// PromoteDeadlineSeconds bounds the whole download->swap->restart->healthy
	// path (card default: <=15 minutes promote-to-healthy under the 5-minute policy).
	PromoteDeadlineSeconds int64 `json:"promoteDeadlineSeconds"`
}

// DefaultUpdatePolicy is the safe default when no policy file is present: check
// every 5 minutes, do NOT auto-apply (notify only), a 2-minute deep-stable hold,
// and a 15-minute promote-to-healthy deadline.
func DefaultUpdatePolicy() UpdatePolicy {
	return UpdatePolicy{
		Schema:                 updatePolicySchema,
		AutoApply:              false,
		PollIntervalSeconds:    300,
		DeepStableSeconds:      120,
		PromoteDeadlineSeconds: 900,
	}
}

func (p UpdatePolicy) validate() error {
	if p.Schema != updatePolicySchema {
		return fmt.Errorf("update-policy schema mismatch: %q", p.Schema)
	}
	if p.PollIntervalSeconds <= 0 {
		return errors.New("pollIntervalSeconds must be positive")
	}
	if p.DeepStableSeconds < 0 {
		return errors.New("deepStableSeconds must be non-negative")
	}
	if p.PromoteDeadlineSeconds <= 0 {
		return errors.New("promoteDeadlineSeconds must be positive")
	}
	// The promote-to-healthy deadline bounds the whole apply, which INCLUDES the
	// deep-stable hold — so it must be at least as long as deep-stable.
	if p.PromoteDeadlineSeconds < p.DeepStableSeconds {
		return fmt.Errorf("promoteDeadlineSeconds %d must be >= deepStableSeconds %d", p.PromoteDeadlineSeconds, p.DeepStableSeconds)
	}
	return nil
}

// LoadUpdatePolicy reads the shell-writable policy file. A MISSING file is not an
// error — it yields the safe DefaultUpdatePolicy (auto-apply OFF). A PRESENT file
// is strictly decoded (unknown field / trailing data refused) and validated;
// defaults fill any zero timing fields before validation so a partial admin edit
// (e.g. only autoApply) is still coherent.
func LoadUpdatePolicy(path string) (UpdatePolicy, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultUpdatePolicy(), nil
		}
		return UpdatePolicy{}, fmt.Errorf("lstat update policy %s: %w", path, err)
	}
	// The policy is shell-writable, but a SYMLINK (redirecting the read elsewhere)
	// or a non-regular file is refused, and the read is size-bounded + no-follow.
	if fi.Mode()&os.ModeSymlink != 0 {
		return UpdatePolicy{}, fmt.Errorf("update policy %s is a symlink; refusing", path)
	}
	if !fi.Mode().IsRegular() {
		return UpdatePolicy{}, fmt.Errorf("update policy %s is not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return UpdatePolicy{}, fmt.Errorf("open update policy %s: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPolicyBytes+1))
	if err != nil {
		return UpdatePolicy{}, fmt.Errorf("read update policy %s: %w", path, err)
	}
	if int64(len(raw)) > maxPolicyBytes {
		return UpdatePolicy{}, fmt.Errorf("update policy %s exceeds %d bytes", path, maxPolicyBytes)
	}
	// Reject case-shadowed/exact duplicate keys (a decoy "AutoApply" shadowing
	// "autoApply") before decoding.
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		return UpdatePolicy{}, fmt.Errorf("update policy %s: %w", path, err)
	}
	p := DefaultUpdatePolicy()
	// Decode over the defaults: absent JSON keys keep their default, present keys
	// override. autoApply defaults to false so its absence stays safe.
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return UpdatePolicy{}, fmt.Errorf("parse update policy %s: %w", path, err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return UpdatePolicy{}, fmt.Errorf("update policy %s: unexpected trailing data", path)
	}
	// A file that sets a timing field to 0 explicitly is coerced back to the safe
	// default rather than an invalid 0 (only autoApply is meaningfully false-able).
	if p.PollIntervalSeconds == 0 {
		p.PollIntervalSeconds = DefaultUpdatePolicy().PollIntervalSeconds
	}
	if p.PromoteDeadlineSeconds == 0 {
		p.PromoteDeadlineSeconds = DefaultUpdatePolicy().PromoteDeadlineSeconds
	}
	if err := p.validate(); err != nil {
		return UpdatePolicy{}, fmt.Errorf("update policy %s: %w", path, err)
	}
	return p, nil
}
