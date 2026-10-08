package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/dossierretention"
)

func readPublic(path string) (ed25519.PublicKey, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("dossier-retention-pin-path-invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("dossier-retention-pin-invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	public, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("dossier-retention-pin-invalid")
	}
	return ed25519.PublicKey(public), nil
}

func readIdentity(keyPath, pinPath string) (ed25519.PrivateKey, error) {
	if !filepath.IsAbs(keyPath) {
		return nil, errors.New("dossier-retention-key-path-invalid")
	}
	info, err := os.Lstat(keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("dossier-retention-key-custody-invalid")
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	private, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("dossier-retention-key-invalid")
	}
	public, err := readPublic(pinPath)
	if err != nil || !bytes.Equal(ed25519.PrivateKey(private).Public().(ed25519.PublicKey), public) {
		return nil, errors.New("dossier-retention-key-pin-mismatch")
	}
	return ed25519.PrivateKey(private), nil
}

func main() {
	root := flag.String("root", "", "absolute durable dossier root outside the pearl")
	pearl := flag.String("pearl-dir", "", "absolute disposable pearl data directory")
	socket := flag.String("socket", "", "absolute private Unix socket path")
	ccashPin := flag.String("ccash-pin", "", "absolute pinned Ccash source public-key file")
	duePin := flag.String("dueprocess-pin", "", "absolute pinned DueProcess public-key file")
	nativePublic := flag.String("native-pin", "", "absolute storage receipt public-key file")
	exportPublic := flag.String("export-pin", "", "absolute member export public-key file")
	flag.Parse()
	if !filepath.IsAbs(*socket) || *socket == "/" {
		log.Fatal("dossier-retention-socket-invalid")
	}
	ccash, err := readPublic(*ccashPin)
	if err != nil {
		log.Fatal(err)
	}
	dueprocess, err := readPublic(*duePin)
	if err != nil {
		log.Fatal(err)
	}
	if !filepath.IsAbs(*root) || *root == "/" {
		log.Fatal("dossier-retention-root-invalid")
	}
	if err := os.MkdirAll(*root, 0700); err != nil {
		log.Fatal(err)
	}
	native, nativeProducedPublic, nativeID, err := dossierretention.LoadOrCreateIdentity(*root, "native")
	if err != nil {
		log.Fatal(err)
	}
	export, exportProducedPublic, exportID, err := dossierretention.LoadOrCreateIdentity(*root, "member")
	if err != nil {
		log.Fatal(err)
	}
	nativePinnedPublic, nativeErr := readPublic(*nativePublic)
	exportPinnedPublic, exportErr := readPublic(*exportPublic)
	if nativeErr != nil || exportErr != nil || !bytes.Equal(nativeProducedPublic, nativePinnedPublic) || !bytes.Equal(exportProducedPublic, exportPinnedPublic) {
		log.Fatal("dossier-retention-key-pin-mismatch")
	}
	store, err := dossierretention.Open(*root, *pearl, ccash, dueprocess, nativeID, native, exportID, export)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(*socket, 0600); err != nil {
		listener.Close()
		log.Fatal(err)
	}
	log.Printf("dossier-retention custody listener ready at %s", *socket)
	if err := http.Serve(listener, store.Handler()); err != nil {
		log.Fatal(err)
	}
}
