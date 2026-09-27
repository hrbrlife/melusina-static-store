package sidecarclasses

import (
	"errors"
	"fmt"
)

// ErrComponentClassMismatch is the named refusal fired when a component's
// on-chain authority kind differs from the table's declared class for its id.
// The suffix carries the exact id: component-class-mismatch:<id>.
func ErrComponentClassMismatch(id, kind, declared string) error {
	return fmt.Errorf("component-class-mismatch:%s: component authority kind %q differs from the signed class table's declared class %q", id, kind, declared)
}

// ErrUnknownComponentRow is the named refusal for a table row that names no
// known component: the table may not invent ids outside the estate's
// component enumeration (G-2 both-directions drift rule).
func ErrUnknownComponentRow(id string) error {
	return fmt.Errorf("unknown-component-row:%s: the sidecar class table names a component absent from the estate's component registry", id)
}

// ErrSidecarRowMissing is the named refusal for an enabled sidecar with no
// table row (the other direction of the drift rule).
func ErrSidecarRowMissing(id string) error {
	return fmt.Errorf("sidecar-row-missing:%s: an enabled sidecar has no declared class in the signed table; the class is never defaulted", id)
}

// ErrTableNotSigned is the fail-closed refusal when a caller reaches for the
// table without a verified one: no default class exists.
var ErrTableNotSigned = errors.New("sidecar class table missing or unverified: the class of every sidecar is a signed estate fact, never defaulted")
