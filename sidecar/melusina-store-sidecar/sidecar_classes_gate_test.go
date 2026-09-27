package main

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/sidecarclasses"
)

// sidecarClassTableFixture signs a minimal table declaring swaprail
// sidecar_identity (matching the promote-test's key-bearing component) and
// mermail sidecar_cascade.
func sidecarClassTableFixture(t *testing.T) sidecarclasses.Table {
	t.Helper()
	op := newTestIdentity(t, "store", testLicenseMint, "bazaar.melusina-os.org")
	doc, err := sidecarclasses.Sign(op, sidecarclasses.Table{
		StoreID:      "melusina-os-root-store",
		SignedAtUnix: 1789000000,
		Rows: []sidecarclasses.Row{
			{ID: "mermail", Class: sidecarclasses.ClassCascade, KeyCustody: sidecarclasses.CustodyNone, DeclaredAt: "2026-09-27T00:00:00Z", Source: "registry.go@0c695588+chaingate.go:262"},
			{ID: "swaprail", Class: sidecarclasses.ClassIdentity, KeyCustody: sidecarclasses.CustodySidecarHeldIdentit, DeclaredAt: "2026-09-27T00:00:00Z", Source: "registry.go@0c695588+repos"},
		},
	})
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
