package storerecovery

import (
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// stateNamespaceHorizon is the highest state generation that StateNamespace
// must be able to name for every storeId an owner-signed profile may state. A
// tenant's installId of at most 58 characters has the same horizon.
const stateNamespaceHorizon = 999

// Seam audit round 1 #18. The storeId is fixed in the owner-signed profile,
// and the profile validator caps it at estateprofile.MaxStoreIDLength. That
// cap is supposed to let this package's StateNamespace name every generation
// up to the horizon for the longest id a profile admits. This test checks the
// bound against the real StateNamespace, not a copy of its rule. The longest
// admitted id must name g1 through g999. One more character must not fit at
// g999, so the cap is also the tightest one. The profile validator's own test
// (estateprofile TestValidateBoundsTheStoreIDToItsStateNamespace) checks that
// it accepts exactly MaxStoreIDLength characters and refuses one more.
func TestStateNamespaceNamesEveryProfileStoreIDThroughTheHorizon(t *testing.T) {
	longest := "s" + strings.Repeat("a", estateprofile.MaxStoreIDLength-1)
	for _, generation := range []uint64{1, 9, 10, 99, 100, stateNamespaceHorizon} {
		if _, err := StateNamespace(longest, generation); err != nil {
			t.Fatalf("STORE_ID_CAP_TOO_LOOSE: the longest storeId a profile admits (%d characters) has no state namespace at g%d: %v", len(longest), generation, err)
		}
	}
	if name, _ := StateNamespace(longest, stateNamespaceHorizon); len(name) != 63 {
		t.Fatalf("STORE_ID_CAP_NOT_TIGHTEST: the longest storeId's namespace at g%d is %q (%d characters), not the 63-character limit", stateNamespaceHorizon, name, len(name))
	}
	if _, err := StateNamespace(longest, stateNamespaceHorizon+1); RefusalName(err) != RefusalStateNamespaceInvalid {
		t.Fatalf("the horizon is g%d, but the longest storeId still names g%d: %v", stateNamespaceHorizon, stateNamespaceHorizon+1, err)
	}
	if _, err := StateNamespace(longest+"a", stateNamespaceHorizon); RefusalName(err) != RefusalStateNamespaceInvalid {
		t.Fatalf("STORE_ID_CAP_NOT_TIGHTEST: a storeId of %d characters still names g%d (%v), so the profile refuses ids its Store could back up", len(longest)+1, stateNamespaceHorizon, err)
	}
}
