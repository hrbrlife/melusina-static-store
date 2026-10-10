package main

import (
	"bytes"
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
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/dossierretention"
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

func socketGroupID(groupName string, numericGID int) (int, error) {
	if groupName == "" {
		if numericGID < 0 {
			return 0, errors.New("evidence-pack-custody-socket-group-missing")
		}
		return numericGID, nil
	}
	if groupName != "melusina" || numericGID >= 0 {
		return 0, errors.New("evidence-pack-custody-socket-group-invalid")
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, errors.New("evidence-pack-custody-socket-group-missing")
	}
	actualGID, err := strconv.Atoi(group.Gid)
	if err != nil || actualGID < 0 {
		return 0, errors.New("evidence-pack-custody-socket-group-invalid")
	}
	return actualGID, nil
}

// The same installer-pinned roster authenticates the Ccash source, Station
// scope and Store member. A roster with competing keys for one source cannot
// silently choose one. The Store member private half must have been produced
// under this durable root before the signed roster was enrolled.
func oneSourcePin(pins map[string]ed25519.PublicKey, owner string) (ed25519.PublicKey, string, error) {
	var public ed25519.PublicKey
	var id string
	for name, candidate := range pins {
		if strings.HasPrefix(name, owner+"/") {
			if id != "" {
				return nil, "", errors.New("evidence-pack-dossier-pin-ambiguous")
			}
			id, public = strings.TrimPrefix(name, owner+"/"), candidate
		}
	}
	if id == "" {
		return nil, "", errors.New("evidence-pack-dossier-pin-missing")
	}
	return public, id, nil
}

func openDossier(root, pearl string, pins map[string]ed25519.PublicKey) (http.Handler, error) {
	ccash, _, err := oneSourcePin(pins, "ccash")
	if err != nil {
		return nil, err
	}
	dueprocess, _, err := oneSourcePin(pins, "dueprocess")
	if err != nil {
		return nil, err
	}
	storage, storageID, err := oneSourcePin(pins, "storage")
	if err != nil {
		return nil, err
	}
	dossierRoot := filepath.Join(root, "dossier-retention")
	if err := os.MkdirAll(dossierRoot, 0700); err != nil {
		return nil, err
	}
	native, _, nativeID, err := dossierretention.LoadOrCreateIdentity(dossierRoot, "native")
	if err != nil {
		return nil, err
	}
	member, memberPublic, memberID, err := dossierretention.LoadOrCreateIdentity(dossierRoot, "member")
	if err != nil {
		return nil, err
	}
	if memberID != storageID || !bytes.Equal(storage, memberPublic) {
		return nil, errors.New("evidence-pack-dossier-signed-roster-drift")
	}
	store, err := dossierretention.Open(dossierRoot, pearl, ccash, dueprocess, nativeID, native, memberID, member)
	if err != nil {
		return nil, err
	}
	return store.Handler(), nil
}

// writeDossierSetupPublic is the pre-enrolment producer for the Store member
// pin. The installer runs this signed binary before assembling the public
// roster; the same durable root is used when the socket service starts. Only
// public halves leave the host. Repeated calls read the first-writer keys.
func writeDossierSetupPublic(root string, output io.Writer) error {
	if !filepath.IsAbs(root) || root == "/" {
		return errors.New("evidence-pack-dossier-setup-root-invalid")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0077 != 0 {
		return errors.New("evidence-pack-dossier-setup-root-invalid")
	}
	dossierRoot := filepath.Join(root, "dossier-retention")
	if err := os.MkdirAll(dossierRoot, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dossierRoot)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("evidence-pack-dossier-setup-root-invalid")
	}
	_, native, nativeID, err := dossierretention.LoadOrCreateIdentity(dossierRoot, "native")
	if err != nil {
		return err
	}
	_, member, memberID, err := dossierretention.LoadOrCreateIdentity(dossierRoot, "member")
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]any{
		"schema": "storage-evidence-pack-setup-keys-v1",
		"keys": []map[string]string{
			{"purpose": "native", "key_id": nativeID, "public_key": base64.RawURLEncoding.EncodeToString(native)},
			{"purpose": "member", "key_id": memberID, "public_key": base64.RawURLEncoding.EncodeToString(member)},
		},
	})
}

func main() {
	root := flag.String("root", "", "absolute durable evidence-pack root")
	setupPublic := flag.Bool("setup-public-only", false, "produce the durable public signer roster before enrolment")
	pearl := flag.String("pearl-dir", "", "absolute disposable grain data directory")
	socket := flag.String("socket", "", "absolute private Unix socket")
	socketGID := flag.Int("socket-gid", -1, "installer-pinned grain socket group ID")
	socketGroup := flag.String("socket-group", "", "installed grain socket group name")
	pinsPath := flag.String("pins", "", "installer-delivered public roster")
	pinsSHA := flag.String("pins-sha256", "", "installer-pinned public roster SHA-256")
	flag.Parse()
	if *setupPublic {
		if *socket != "" || *pinsPath != "" || *pinsSHA != "" || *pearl != "" || *socketGID >= 0 || *socketGroup != "" {
			log.Fatal("evidence-pack-dossier-setup-flags-invalid")
		}
		if err := writeDossierSetupPublic(*root, os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	if !filepath.IsAbs(*socket) || *socket == "/" {
		log.Fatal("evidence-pack-custody-socket-invalid")
	}
	resolvedGID, err := socketGroupID(*socketGroup, *socketGID)
	if err != nil {
		log.Fatal(err)
	}
	pins, err := loadPins(*pinsPath, *pinsSHA)
	if err != nil {
		log.Fatal(err)
	}
	custody, err := packcustody.Open(*root, *pearl, pins)
	if err != nil {
		log.Fatal(err)
	}
	dossier, err := openDossier(*root, *pearl, pins)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatal(err)
	}
	if err := setSocketAccess(*socket, resolvedGID); err != nil {
		listener.Close()
		log.Fatal(err)
	}
	log.Printf("evidence-pack custody listener ready at %s", *socket)
	routes := http.NewServeMux()
	routes.Handle("POST /v1/dossier", dossier)
	routes.Handle("/", custody.Handler())
	if err := http.Serve(listener, routes); err != nil {
		log.Fatal(err)
	}
}
