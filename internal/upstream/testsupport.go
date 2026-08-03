package upstream

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// RequireRealNFT skips t unless nft/ip work inside a throwaway unprivileged
// netns (unshare + nsenter, never real root). Swaps ipBin/nftBin for t's
// duration, returns the nft binary callers should verify against.
func RequireRealNFT(t *testing.T) (nft string) {
	t.Helper()
	nftReal, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not on PATH")
	}
	ipReal, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("ip not on PATH")
	}
	prevIP, prevNft := ipBin, nftBin
	t.Cleanup(func() { ipBin, nftBin = prevIP, prevNft })

	holder := exec.Command("unshare", "--user", "--net", "--map-root-user", "--", "sleep", "3600")
	if err := holder.Start(); err != nil {
		t.Skipf("rootless netns unavailable (unshare): %v", err)
	}
	t.Cleanup(func() { holder.Process.Kill(); holder.Wait() })
	pid := strconv.Itoa(holder.Process.Pid)

	dir := t.TempDir()
	ipBin = nsWrap(t, dir, "ip", pid, ipReal)
	nftBin = nsWrap(t, dir, "nft", pid, nftReal)

	// A fresh netns's lo exists but starts administratively down — routing
	// tests that use it (the one interface guaranteed to exist anywhere)
	// need it up first.
	if out, err := exec.Command(ipBin, "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Skipf("rootless netns: bringing up lo failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(nftBin, "list", "tables").CombinedOutput(); err != nil {
		t.Skipf("rootless netns nft probe failed: %v\n%s", err, out)
	}
	return nftBin
}

// nsWrap writes a wrapper script that re-enters holder's (pid) net+user
// namespace before exec'ing realBin.
func nsWrap(t *testing.T, dir, name, pid, realBin string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := fmt.Sprintf("#!/bin/sh\nexec nsenter --target %s --net --user --preserve-credentials -- %s \"$@\"\n", pid, realBin)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
