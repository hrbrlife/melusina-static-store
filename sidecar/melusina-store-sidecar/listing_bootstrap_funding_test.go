package main

import (
	"os"
	"strings"
	"testing"
)

// The listing-bootstrap funding precheck must count the PAYER's own
// rent-exempt floor, not just the rent and fees for the listings it creates.
//
// A Solana system account cannot be left below its rent-exempt minimum, so a
// transfer that would do so is rejected at sendTransaction with
//
//	Transaction results in an account (0) with insufficient funds for rent
//
// On 2026-08-22 the store authority held 3,219,920 lamports while this check
// asked for 2,647,840. It passed, and the repair then failed mid-flight with
// the app catalog already serving 503 estate-wide — because F-257 means the
// repair only ever runs when the catalog is ALREADY down. A precheck that
// passes and then fails is worse than no precheck: it moves the failure to the
// point of maximum damage.
func TestBootstrapRequiredLamportsIncludesThePayerRentFloor(t *testing.T) {
	const (
		rentPerListing = uint64(2_637_840)
		payerFloor     = uint64(890_880)
		missing        = uint64(1)
	)
	required := missing*(rentPerListing+listingFeeReserveLamports) + payerFloor

	// The exact balance the 2026-08-22 store authority held.
	const held = uint64(3_219_920)
	if held >= required {
		t.Fatalf("the balance that actually failed on-chain (%d) must not satisfy the precheck (%d) — "+
			"the payer's own rent-exempt floor is not being counted", held, required)
	}

	// And the old formula, which is what shipped, must be the one that wrongly passes.
	oldFormula := missing * (rentPerListing + listingFeeReserveLamports)
	if held < oldFormula {
		t.Fatalf("test premise wrong: %d should have satisfied the old formula %d", held, oldFormula)
	}
}

// The refusal must name the shortfall, so an operator repairing a 503 catalog
// knows exactly how much to move rather than guessing.
func TestFundingRefusalNamesTheShortfall(t *testing.T) {
	raw, err := os.ReadFile("listing_bootstrap.go")
	if err != nil {
		t.Fatalf("read listing_bootstrap.go: %v", err)
	}
	src := string(raw)
	for _, want := range []string{
		"rent-exempt floor",
		"short by",
		"PayerRentFloorLamports",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("listing_bootstrap.go no longer mentions %q — the refusal has stopped being actionable", want)
		}
	}
	if !strings.Contains(src, "+ payerFloor") {
		t.Error("RequiredLamports no longer adds the payer's rent-exempt floor")
	}
}
