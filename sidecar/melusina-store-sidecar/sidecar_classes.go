package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// This wire format and domain are the deployer's sidecarclasses v1 contract.
// Rows come only from the current operator-signed generation; no file in the
// served tree can declare or override a class.
const sidecarClassesDomain = "melusina-sidecar-classes-v1\x00"

type sidecarClassRow struct {
	ID         string `json:"id"`
	Class      string `json:"class"`
	KeyCustody string `json:"keyCustody"`
	DeclaredAt string `json:"declaredAt"`
	Source     string `json:"source"`
}

type sidecarClassTable struct {
	Schema            string            `json:"schema"`
	StoreID           string            `json:"storeId"`
	OperatorPubkey    string            `json:"operatorPubkey"`
	SignedAtUnix      int64             `json:"signedAtUnix"`
	Rows              []sidecarClassRow `json:"rows"`
	OperatorSignature string            `json:"operatorSignature"`
}

func classString(dst []byte, value string) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}

func classSigningMessage(t sidecarClassTable) ([]byte, error) {
	if t.Schema != "melusina.sidecar-classes.v1" || t.StoreID == "" || t.OperatorPubkey == "" ||
		t.SignedAtUnix <= 0 || len(t.Rows) == 0 || len(t.Rows) > 4096 {
		return nil, errors.New("sidecar class table is incomplete")
	}
	content := append([]byte(nil), sidecarClassesDomain...)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(t.Rows)))
	content = append(content, count[:]...)
	for i, row := range t.Rows {
		if row.ID == "" || row.Source == "" || row.DeclaredAt == "" ||
			(i > 0 && t.Rows[i-1].ID >= row.ID) {
			return nil, errors.New("sidecar class rows are not unique and sorted")
		}
		if _, err := time.Parse(time.RFC3339, row.DeclaredAt); err != nil {
			return nil, fmt.Errorf("sidecar class declaration time: %w", err)
		}
		if (row.Class == componentrelease.AuthoritySidecarCascade && row.KeyCustody != "none") ||
			(row.Class == componentrelease.AuthoritySidecarIdentity && row.KeyCustody != "sidecar-held-identity") ||
			!componentrelease.IsSidecarAuthority(row.Class) {
			return nil, fmt.Errorf("sidecar class mismatch for %s", row.ID)
		}
		rowBytes := append([]byte(nil), sidecarClassesDomain...)
		for _, field := range []string{row.ID, row.Class, row.KeyCustody, row.DeclaredAt, row.Source} {
			rowBytes = classString(rowBytes, field)
		}
		hash := sha256.Sum256(rowBytes)
		content = append(content, hash[:]...)
	}
	contentHash := sha256.Sum256(content)
	message := append([]byte(nil), sidecarClassesDomain...)
	for _, field := range []string{t.Schema, t.StoreID, t.OperatorPubkey} {
		message = classString(message, field)
	}
	var at [8]byte
	binary.BigEndian.PutUint64(at[:], uint64(t.SignedAtUnix))
	message = append(message, at[:]...)
	return append(message, contentHash[:]...), nil
}

func (s *publishService) classesFromGeneration(doc componentrelease.DesiredGeneration) (sidecarClassTable, error) {
	if s.operator == nil {
		return sidecarClassTable{}, errors.New("sidecar class operator identity unavailable")
	}
	t := sidecarClassTable{
		Schema: "melusina.sidecar-classes.v1", StoreID: doc.StoreID,
		OperatorPubkey: doc.OperatorPubkey, SignedAtUnix: doc.SignedAtUnix,
		Rows: make([]sidecarClassRow, 0),
	}
	for _, c := range doc.Components {
		if c.ComponentClass != componentrelease.ClassSidecar {
			continue
		}
		if !componentrelease.IsSidecarAuthority(c.Chain.Kind) || c.Chain.SidecarID == "" {
			return sidecarClassTable{}, fmt.Errorf("sidecar class mismatch for %s", c.ComponentID)
		}
		custody := "none"
		if c.Chain.Kind == componentrelease.AuthoritySidecarIdentity {
			custody = "sidecar-held-identity"
		}
		t.Rows = append(t.Rows, sidecarClassRow{
			ID: c.ComponentID, Class: c.Chain.Kind, KeyCustody: custody,
			DeclaredAt: time.Unix(doc.SignedAtUnix, 0).UTC().Format(time.RFC3339),
			Source:     doc.GenerationHash,
		})
	}
	sort.Slice(t.Rows, func(i, j int) bool { return t.Rows[i].ID < t.Rows[j].ID })
	message, err := classSigningMessage(t)
	if err != nil {
		return sidecarClassTable{}, err
	}
	t.OperatorSignature = primitives.EncodeBase58(s.operator.Sign(message))
	return t, nil
}

func (s *publishService) handleSidecarClasses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, _, err := s.loadVerifiedDesiredGeneration()
	if err == nil {
		err = s.verifyDesiredGenerationServeSurface(doc)
	}
	var table sidecarClassTable
	if err == nil {
		table, err = s.classesFromGeneration(doc)
	}
	if err != nil {
		http.Error(w, "check=sidecar_classes: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_ = json.NewEncoder(w).Encode(table)
}
