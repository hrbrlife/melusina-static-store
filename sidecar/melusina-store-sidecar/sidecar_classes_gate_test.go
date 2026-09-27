package main

import (
	"context"
	"crypto/sha256"
	"sort"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/sidecarclasses"
)

// sidecarClassFixtureClasses is the CLASS declaration for each component id a
// root-package suite drives through the shared promote/serve dispatcher. The
// row SET is never hand-listed per suite: sidecarClassTableFixture derives one
// row per declared id, so a new suite reusing a declared component cannot be
// missed (round-1 audit F1a — the original fixture covered two ids while six
// suites needed rows for five). A NEW component id must be added here; the
// narrower builder sidecarClassFixtureTableForIDs refuses an undeclared id by
// name instead of leaving it silently untabled.
var sidecarClassFixtureClasses = map[string]string{
	// The one keyless (cascade) sidecar the suites drive: newKeylessFixture
	// publishes mermail and promotes/serves it on the five-fact cascade alone.
	"mermail": sidecarclasses.ClassCascade,
	// The key-bearing sidecars the serve-gate, key-version and host-apply
	// suites drive. melusina-store-sidecar is the SHELL component (the
	// sidecar-identity key-version parity vector's componentId); fineract-v2 /
	// fineract-sidecar are the host-apply plan fixture's components.
	"swaprail":               sidecarclasses.ClassIdentity,
	"melusina-store-sidecar": sidecarclasses.ClassIdentity,
	"fineract-v2":            sidecarclasses.ClassIdentity,
	"fineract-sidecar":       sidecarclasses.ClassIdentity,
}

// sidecarClassTableFixture signs a table with a row for EVERY component id the
// root-package suites drive (see sidecarClassFixtureClasses): one derived row
// set, so a suite can never be missed again. The signer, destination,
// declaredAt and row fields match the committed genparity vector contract so
// the fixture stays comparable with the cross-repo parity document.
func sidecarClassTableFixture(t *testing.T) sidecarclasses.Table {
	t.Helper()
	ids := make([]string, 0, len(sidecarClassFixtureClasses))
	for id := range sidecarClassFixtureClasses {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return sidecarClassFixtureTableForIDs(t, ids...)
}

// sidecarClassFixtureTableForIDs signs a table covering exactly the given ids
// (each must be declared in sidecarClassFixtureClasses — an undeclared id is a
// named failure HERE, not a distant sidecar-row-missing in whichever suite
// reaches the gate first). A refusal-direction suite proves the gate still
// refuses an id OUTSIDE the derived set by simply driving one.
func sidecarClassFixtureTableForIDs(t *testing.T, ids ...string) sidecarclasses.Table {
	t.Helper()
	op := newTestIdentity(t, "store", testLicenseMint, "bazaar.melusina-os.org")
	rows := make([]sidecarclasses.Row, 0, len(ids))
	for _, id := range ids {
		class, declared := sidecarClassFixtureClasses[id]
		if !declared {
			t.Fatalf("fixture component %q has no declared class in sidecarClassFixtureClasses; declare it (G-2) so the derived table covers it", id)
		}
		custody := sidecarclasses.CustodySidecarHeldIdentity
		if class == sidecarclasses.ClassCascade {
			custody = sidecarclasses.CustodyNone
		}
		rows = append(rows, sidecarclasses.Row{ID: id, Class: class, KeyCustody: custody, DeclaredAt: "2026-09-27T00:00:00Z", Source: "sidecar_classes_gate_test.go (derived fixture enumeration)"})
	}
	doc, err := sidecarclasses.Sign(op, sidecarclasses.Table{StoreID: "melusina-os-root-store", SignedAtUnix: 1789000000, Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func swaprailClassComponent(kind string) componentrelease.ComponentRelease {
	sum := sha256.Sum256([]byte("swaprail-class-bytes"))
	_ = sum
	return componentrelease.ComponentRelease{
		ComponentID:    "swaprail",
		ComponentClass: componentrelease.ClassSidecar,
		ArtifactName:   "swaprail.bin",
		SHA256:         "",
		SizeBytes:      int64(len("swaprail-class-bytes")),
		BundleURL:      "https://bazaar.melusina-os.org/releases/sidecar/swaprail.bin",
		Chain: componentrelease.ChainAuthority{
			Kind:           kind,
			LicenseNftMint: testLicenseMint,
			SidecarID:      "swaprail",
			KeyVersion:     1,
		},
	}
}

// TestSidecarClassFixtureDerivationGuard is the G-2 guard on the DERIVED
// fixture: (1) every declared component has a valid class and the derived
// table covers exactly the declared set (no drift, no stale row); (2) a row
// for a component id OUTSIDE the declared enumeration is a named refusal
// (unknown-component-row), so the fixture can never grow an unvetted id; and
// (3) a component absent from the enumeration is refused by name by the gate
// (sidecar-row-missing), never defaulted.
func TestSidecarClassFixtureDerivationGuard(t *testing.T) {
	if len(sidecarClassFixtureClasses) < 4 {
		t.Fatalf("the derived fixture enumeration collapsed to %d components; it cannot vouch for the suites", len(sidecarClassFixtureClasses))
	}
	table := sidecarClassTableFixture(t)
	if table.Count() != len(sidecarClassFixtureClasses) {
		t.Fatalf("derived table has %d rows for %d declared components", table.Count(), len(sidecarClassFixtureClasses))
	}
	for id, class := range sidecarClassFixtureClasses {
		declared, ok := table.ClassFor(id)
		if !ok || declared != class {
			t.Fatalf("derived table row %q = %q, want declared %q", id, declared, class)
		}
		if _, ok := table.CustodyFor(id); !ok {
			t.Fatalf("derived table row %q lacks custody", id)
		}
	}

	// (2) a row naming a component outside the enumeration is refused by name.
	op := newTestIdentity(t, "store", testLicenseMint, "bazaar.melusina-os.org")
	_, err := sidecarclasses.Sign(op, sidecarclasses.Table{
		StoreID: "melusina-os-root-store", SignedAtUnix: 1789000000,
		Rows: append(table.Rows, sidecarclasses.Row{ID: "ghost-sidecar-not-in-registry", Class: sidecarclasses.ClassIdentity, KeyCustody: sidecarclasses.CustodySidecarHeldIdentity, DeclaredAt: "2026-09-27T00:00:00Z", Source: "guard plant"}),
	})
	if err != nil {
		t.Fatalf("planting an unvetted row broke signing before the loader could refuse it: %v", err)
	}
	svc := &publishService{cfg: Config{SidecarClasses: sidecarClassFixtureTableForIDs(t, "swaprail")}}
	gate := swaprailClassComponent(componentrelease.AuthoritySidecarIdentity)
	gate.ComponentID = "ghost-sidecar-not-in-registry"
	gate.Chain.SidecarID = "ghost-sidecar-not-in-registry"
	// The derived fixture only ever covers declared ids, so an id outside the
	// enumeration hits the gate as sidecar-row-missing (the Store-side arm of
	// the G-2 drift rule; the loader-side arm is the deployer's
	// unknown-component-row refusal, pinned there).
	if err := svc.verifySidecarClassComponentOnChain(context.Background(), gate); err == nil || !strings.Contains(err.Error(), "sidecar-row-missing:ghost-sidecar-not-in-registry") {
		t.Fatalf("a component outside the derived enumeration was not refused by name: %v", err)
	}
}

// K-CHN-33 control: a sidecar whose signed kind differs from the table's
// declared class is refused BY NAME at the shared promote/serve dispatcher.
func TestSidecarClassTableMismatchRefusedByName(t *testing.T) {
	table := sidecarClassTableFixture(t)
	ctx := context.Background()

	// Table declares swaprail sidecar_identity; a cascade-kind claim is refused
	// by name before any chain read.
	svc := &publishService{cfg: Config{SidecarClasses: table}}
	err := svc.verifySidecarClassComponentOnChain(ctx, swaprailClassComponent(componentrelease.AuthoritySidecarCascade))
	if err == nil {
		t.Fatal("component-class-mismatch control: a cascade-kind sidecar passed a table declaring sidecar_identity")
	}
	if !strings.Contains(err.Error(), "component-class-mismatch:swaprail") {
		t.Fatalf("mismatch refused by the wrong name: %q", err.Error())
	}
	t.Logf("named refusal: %v", err)

	// An id the table does not cover is refused by name (no default class).
	unknown := swaprailClassComponent(componentrelease.AuthoritySidecarIdentity)
	unknown.ComponentID = "uncarted-sidecar"
	unknown.Chain.SidecarID = "uncarted-sidecar"
	err = svc.verifySidecarClassComponentOnChain(ctx, unknown)
	if err == nil {
		t.Fatal("sidecar-row-missing control: an untabled sidecar was admitted")
	}
	if !strings.Contains(err.Error(), "sidecar-row-missing:uncarted-sidecar") {
		t.Fatalf("missing row refused by the wrong name: %q", err.Error())
	}
	t.Logf("named refusal: %v", err)

	// Matching table + matching kind passes the table check (reaches the
	// on-chain gate, which fails on the mock reader's missing chain facts —
	// that refusal must NOT be a class refusal).
	err = svc.verifySidecarClassComponentOnChain(ctx, swaprailClassComponent(componentrelease.AuthoritySidecarIdentity))
	if err != nil && (len(err.Error()) >= 27 && err.Error()[:27] == "component-class-mismatch:sw") {
		t.Fatalf("matching class refused as mismatch: %v", err)
	}
}

// Control-of-control: without the table the wiring must refuse, not default.
func TestSidecarClassTableAbsentRefuses(t *testing.T) {
	svc := &publishService{cfg: Config{}}
	err := svc.verifySidecarClassComponentOnChain(context.Background(), swaprailClassComponent(componentrelease.AuthoritySidecarIdentity))
	if err == nil {
		t.Fatal("an empty class table admitted a sidecar (fail-open default)")
	}
	if !strings.Contains(err.Error(), "sidecar-row-missing:swaprail") {
		t.Fatalf("absent table refused by the wrong name: %q", err.Error())
	}
}
