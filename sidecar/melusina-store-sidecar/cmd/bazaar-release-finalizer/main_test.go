package main

import (
	"context"
	"testing"
)

func TestCommandAcceptsOnlyInstalledConfig(t *testing.T) {
	for _, args := range [][]string{nil, {"-config", "/missing"}, {"-config", "/missing", "command"}, {"-command", "sh"}, {"-rpc", "https://rpc.invalid"}} {
		if err := run(context.Background(), args); err == nil {
			t.Fatal("command accepted an absent config or request-selected backend")
		}
	}
}
