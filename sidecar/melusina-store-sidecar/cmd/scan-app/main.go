package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/appscan"
)

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("scan-app requires keygen or scan"))
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "scan":
		err = scan(os.Args[2:])
	default:
		err = errors.New("scan-app unknown command")
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "new 0600 Ed25519 seed path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errors.New("scan-app-keygen-out-required")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(private.Seed()); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(public))
	return nil
}

func scan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	spk := fs.String("spk", "", "SPK file")
	metadata := fs.String("metadata", "", "metadata JSON file")
	release := fs.String("release", "", "RELEASE JSON file")
	target := fs.String("target", "", "exact Store control prepare or publish route")
	runtime := fs.String("runtime-contract", "", "optional runtime contract file")
	keyPath := fs.String("signing-key", "", "0600 scanner seed from keygen")
	database := fs.String("database", "/var/lib/clamav", "ClamAV database directory")
	workDir := fs.String("work-dir", "", "private staging parent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *spk == "" || *metadata == "" || *release == "" || *target == "" || *keyPath == "" || *workDir == "" || fs.NArg() != 0 {
		return errors.New("scan-app-required-input-missing")
	}
	seedInfo, err := os.Lstat(*keyPath)
	if err != nil || !seedInfo.Mode().IsRegular() || seedInfo.Mode().Perm() != 0o600 {
		return errors.New("scan-app-signing-key-must-be-regular-0600")
	}
	seed, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	if len(seed) != ed25519.SeedSize {
		return errors.New("scan-app-invalid-seed")
	}
	paths := []string{*spk, *metadata, *release, *runtime}
	content := make([][]byte, 4)
	for i, path := range paths {
		if i == 3 && path == "" {
			content[i] = []byte{}
			continue
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("scan-app-input-must-be-regular-file")
		}
		content[i], err = os.ReadFile(path)
		if err != nil {
			return err
		}
	}
	version, dbVersion, err := appscan.ScanFiles([4][]byte{content[0], content[1], content[2], content[3]}, *database, *workDir)
	if err != nil {
		return err
	}
	r := appscan.Report{Schema: appscan.Schema, Method: "POST", Target: *target, SPKSHA256: appscan.Hash(content[0]), MetadataSHA256: appscan.Hash(content[1]), ReleaseSHA256: appscan.Hash(content[2]), RuntimeContractSHA256: appscan.Hash(content[3]), ScannedAtUnix: time.Now().UTC().Unix(), ScannerVersion: version, DatabaseVersion: dbVersion, Clean: true}
	if err := r.Sign(ed25519.NewKeyFromSeed(seed)); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(r)
}
