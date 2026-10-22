package main

import (
	"net/http"
	"testing"
)

func TestPrivateCatalogReadbackAcceptsSignedRouteStaticAndProjectedStore(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		gate   string
		want   bool
	}{
		{"pre-listing-static-index", http.StatusOK, "", true},
		{"post-listing-projected-index", http.StatusOK, "verified", true},
		{"foreign-gate-marker", http.StatusOK, "foreign", false},
		{"unserved-index", http.StatusServiceUnavailable, "", false},
		{"redirect", http.StatusFound, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := admitCatalogReadback(tc.status, tc.gate); got != tc.want {
				t.Fatalf("PRIVATE_CATALOG_%s: got %t, want %t", tc.name, got, tc.want)
			}
		})
	}
}
