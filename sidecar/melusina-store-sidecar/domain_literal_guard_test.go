package main

import (
	"os/exec"
	"testing"
)

func TestEstateDomainLiteralGuard(t *testing.T) {
	out, err := exec.Command("python3", "../../scripts/test-domain-literals.py").CombinedOutput()
	if err != nil {
		t.Fatalf("estate domain literal guard: %v\n%s", err, out)
	}
	t.Log(string(out))
}
