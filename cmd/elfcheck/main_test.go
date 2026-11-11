package main

import (
	"os"
	"strings"
	"testing"
)

// go test links its binary as a plain executable, so it must be refused; the
// hardened case is make check's own build of bin/ovcp.
func TestRefusesNonPIE(t *testing.T) {
	err := check(os.Args[0])
	if err == nil || !strings.Contains(err.Error(), "PIE") {
		t.Fatalf("check(test binary) = %v, want missing PIE", err)
	}
}
