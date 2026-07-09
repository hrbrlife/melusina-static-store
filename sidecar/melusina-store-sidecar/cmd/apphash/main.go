// Command apphash prints the canonical on-chain AppHash for an SPK + its
// metadata.json — the exact tree-hash the serve-gate recomputes
// (apphash.Canonical over {app.spk, metadata.json}) and compares against the
// on-chain ReleaseEntry.app_hash. A read-only diagnostic: given a package dir
// (containing app.spk + metadata.json) it prints the appHash, so a publisher
// can tell whether a served RELEASE.json / on-chain entry actually matches the
// bytes being served.
//
// Usage:
//
//	apphash <dir-with-app.spk-and-metadata.json>
//	apphash -spk <path> -metadata <path>
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
)

func main() {
	spk := flag.String("spk", "", "path to app.spk")
	meta := flag.String("metadata", "", "path to metadata.json")
	flag.Parse()
	if *spk == "" || *meta == "" {
		if flag.NArg() == 1 {
			dir := flag.Arg(0)
			*spk = filepath.Join(dir, "app.spk")
			*meta = filepath.Join(dir, "metadata.json")
		} else {
			fmt.Fprintln(os.Stderr, "usage: apphash <dir> | apphash -spk <p> -metadata <p>")
			os.Exit(2)
		}
	}
	f, err := os.Open(*spk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open spk: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	metadata, err := os.ReadFile(*meta)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read metadata: %v\n", err)
		os.Exit(1)
	}
	h, err := apphash.Canonical(f, metadata)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apphash: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(h)
}
