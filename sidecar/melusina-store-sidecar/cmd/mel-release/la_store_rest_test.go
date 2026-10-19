package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLAStoreRestFrozenCatalogLoadsAndAdmitsFourteen(t *testing.T) {
	path := os.Getenv("LA_STORE_REST_PROJECTED_CATALOG")
	if path == "" {
		t.Skip("LA_STORE_REST_PROJECTED_CATALOG absent")
	}
	catalog, err := LoadCatalog(path)
	if err != nil || len(catalog.Apps) != 14 || catalog.ExpectedLiveAppCount != 14 {
		t.Fatalf("LA_STORE_REST_GO_CATALOG_14_REFUSED: %v", err)
	}
	for _, app := range catalog.Apps {
		if err := app.RequireReleaseReady(); err != nil {
			t.Fatalf("LA_STORE_REST_GO_FROZEN_APP_HELD:%s: %v", app.AppID, err)
		}
	}
	old, err := LoadCatalog(filepath.Join("..", "..", "..", "..", "fleet", "bazaar-catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cyberteller, err := old.Select("vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0")
	if err != nil || cyberteller.RequireReleaseReady() == nil {
		t.Fatal("LA_STORE_REST_OLD_CYBERTELLER_HOLD_BYPASSED")
	}
}
