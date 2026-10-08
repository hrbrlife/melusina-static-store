package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/packcustody"
)

// loadPins consumes the exact public roster digest from the installer plan.
// The runtime cannot accept a roster or an expected digest in an HTTP request.
func loadPins(path, expectedSHA256 string) (map[string]ed25519.PublicKey, error) {
	if !filepath.IsAbs(path) || len(expectedSHA256) != 64 {
		return nil, errors.New("evidence-pack-custody-pins-unenrolled")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("evidence-pack-custody-pins-invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expectedSHA256 {
		return nil, errors.New("evidence-pack-custody-pins-drift")
	}
	var envelope struct {
		Keys map[string]string `json:"keys"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF || len(envelope.Keys) == 0 {
		return nil, errors.New("evidence-pack-custody-pins-invalid")
	}
	pins := make(map[string]ed25519.PublicKey, len(envelope.Keys))
	for id, encoded := range envelope.Keys {
		value, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(value) != ed25519.PublicKeySize {
			return nil, errors.New("evidence-pack-custody-pins-invalid")
		}
		pins[id] = ed25519.PublicKey(value)
	}
	return pins, nil
}

// The Shell grants the grain's mapped group access to this one socket. The
// installer owns the numeric group in the service unit; requests cannot alter
// it. Refuse an unset group instead of creating a root-only dead transport.
func setSocketAccess(path string, gid int) error {
	if gid < 0 {
		return errors.New("evidence-pack-custody-socket-group-missing")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return errors.New("evidence-pack-custody-socket-invalid")
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return err
	}
	if err := os.Chmod(path, 0660); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if err != nil {
		return errors.New("evidence-pack-custody-socket-access-invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode().Perm() != 0660 || stat.Gid != uint32(gid) {
		return errors.New("evidence-pack-custody-socket-access-invalid")
	}
	return nil
}

func main() {
	root := flag.String("root", "", "absolute durable evidence-pack root")
	pearl := flag.String("pearl-dir", "", "absolute disposable grain data directory")
	socket := flag.String("socket", "", "absolute private Unix socket")
	socketGID := flag.Int("socket-gid", -1, "installer-pinned grain socket group ID")
	pinsPath := flag.String("pins", "", "installer-delivered public roster")
	pinsSHA := flag.String("pins-sha256", "", "installer-pinned public roster SHA-256")
	flag.Parse()
	if !filepath.IsAbs(*socket) || *socket == "/" {
		log.Fatal("evidence-pack-custody-socket-invalid")
	}
	pins, err := loadPins(*pinsPath, *pinsSHA)
	if err != nil {
		log.Fatal(err)
	}
	custody, err := packcustody.Open(*root, *pearl, pins)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatal(err)
	}
	if err := setSocketAccess(*socket, *socketGID); err != nil {
		listener.Close()
		log.Fatal(err)
	}
	log.Printf("evidence-pack custody listener ready at %s", *socket)
	if err := http.Serve(listener, custody.Handler()); err != nil {
		log.Fatal(err)
	}
}
