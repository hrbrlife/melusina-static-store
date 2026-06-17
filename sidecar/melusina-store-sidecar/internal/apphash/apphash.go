// Package apphash computes the Melusina on-chain ReleaseEntry AppHash: the sorted
// TREE-HASH over a staged app tree that the pearl ceremony registers on-chain,
// NOT sha256(spk). It is a self-contained port of the contract in the attest
// deployer tool's internal/apphash (which cannot be imported across modules), so
// the store sidecar's serve + publish gates AND the publish client (cmd/submit)
// all reproduce the EXACT same hash from one implementation — no divergence.
//
// Algorithm, fixed by the ReleaseEntry contract (internal/apphash/apphash.go in
// melusina-attestdeployer-tool):
//
//  1. sort files by forward-slash relative path;
//  2. H_i = SHA256("F " ‖ rel_path ‖ 0x00 ‖ file_bytes);
//  3. AppHash = hex_lower(SHA256(H_1 ‖ H_2 ‖ … ‖ H_n)).
//
// Mode bits are NOT hashed (the SPK archive carries its own mode metadata; a chmod
// on a workstation must not invalidate a release). The pearl ceremony stages
// EXACTLY {app.spk, metadata.json} (static_store/scripts/pearl-app-ceremony.sh;
// description.md / icon / changelog are excluded), so Canonical hashes that pair.
package apphash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
)

// Canonical staged-tree file names — the only two files the pearl ceremony stages.
const (
	SPKName      = "app.spk"
	MetadataName = "metadata.json"
)

// File is one entry of the staged app tree: its forward-slash relative path and a
// reader over its EXACT bytes. The reader is consumed once, in sorted-path order,
// so a streaming source (an open SPK fd) is hashed without buffering the whole
// package in memory.
type File struct {
	RelPath string
	R       io.Reader
}

// Compute reproduces the apphash contract for an explicit file set: sort by
// forward-slash rel path, fold each file's inner hash
// SHA256("F " ‖ rel_path ‖ 0x00 ‖ bytes) into the outer hash, and return
// hex_lower(SHA256(‖ inner_i)).
func Compute(files []File) (string, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].RelPath < files[j].RelPath })
	outer := sha256.New()
	for _, f := range files {
		inner := sha256.New()
		inner.Write([]byte("F "))
		inner.Write([]byte(f.RelPath))
		inner.Write([]byte{0})
		if _, err := io.Copy(inner, f.R); err != nil {
			return "", fmt.Errorf("apphash: hash %s: %w", f.RelPath, err)
		}
		outer.Write(inner.Sum(nil))
	}
	return hex.EncodeToString(outer.Sum(nil)), nil
}

// Canonical computes the on-chain AppHash for a catalog app from its two staged
// files: the SPK bytes (streamed from spk — never fully buffered) and the exact
// metadata.json bytes. This is THE binding the serve + publish gates check against
// rel.AppHash and the on-chain ReleaseEntry.
func Canonical(spk io.Reader, metadata []byte) (string, error) {
	return Compute([]File{
		{RelPath: SPKName, R: spk},
		{RelPath: MetadataName, R: bytes.NewReader(metadata)},
	})
}
