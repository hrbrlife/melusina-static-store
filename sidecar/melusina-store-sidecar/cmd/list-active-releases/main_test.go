package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeSandstormAppIDKnownVector(t *testing.T) {
	got, err := decodeSandstormAppID("vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0")
	if err != nil {
		t.Fatal(err)
	}
	if want := "dd621583e52c72fcdf1b306b510cf0174f9e80f0cfd269e8ff6a45f29d5a4b20"; hex.EncodeToString(got[:]) != want {
		t.Fatalf("decoded appId %x, want %s", got, want)
	}
}

func TestGetProgramAccountsStrictResponseAndBound(t *testing.T) {
	var appID [32]byte
	valid := `{"jsonrpc":"2.0","id":1,"result":[]}`
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "valid-empty", body: valid},
		{name: "duplicate-id", body: `{"jsonrpc":"2.0","id":1,"ID":1,"result":[]}`, want: "duplicate"},
		{name: "unknown-field", body: `{"jsonrpc":"2.0","id":1,"result":[],"shadow":true}`, want: "unknown field"},
		{name: "missing-result", body: `{"jsonrpc":"2.0","id":1}`, want: "omits result"},
		{name: "wrong-id", body: `{"jsonrpc":"2.0","id":2,"result":[]}`, want: "jsonrpc/id mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			_, err := getProgramAccountsByAppID(context.Background(), srv.URL, defaultLicenseProgramID, appID)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestGetProgramAccountsRejectsOversizedResponse(t *testing.T) {
	var appID [32]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, strings.Repeat("x", (16<<20)+1))
	}))
	defer srv.Close()
	if _, err := getProgramAccountsByAppID(context.Background(), srv.URL, defaultLicenseProgramID, appID); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response accepted: %v", err)
	}
}

func TestDecodeSandstormAppIDRejectsMalformed(t *testing.T) {
	for _, value := range []string{
		"short",
		"vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dhi",
		"vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh1",
	} {
		if _, err := decodeSandstormAppID(value); err == nil {
			t.Fatalf("accepted malformed appId %q", value)
		}
	}
}
