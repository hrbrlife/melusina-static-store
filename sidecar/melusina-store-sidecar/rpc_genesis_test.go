package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifyRPCGenesisExactMatchAndMismatch(t *testing.T) {
	const genesis = "BSENx6t1GVPzhnnd4yiojxWk7HjKZiiRQEkriHg6Mpix"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%q}`, genesis)
	}))
	defer srv.Close()
	if err := verifyRPCGenesis(context.Background(), srv.URL, genesis); err != nil {
		t.Fatal(err)
	}
	if err := verifyRPCGenesis(context.Background(), srv.URL, "11111111111111111111111111111111"); err == nil || !strings.Contains(err.Error(), "cluster genesis mismatch") {
		t.Fatalf("mismatch error = %v", err)
	}
}
