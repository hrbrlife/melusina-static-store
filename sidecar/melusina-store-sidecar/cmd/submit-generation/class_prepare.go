package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/publishclient"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const classPreparePath = "/publish/sidecar-classes"
const classDomain = "melusina-sidecar-classes-v1\x00"

type classPrepareRow struct {
	ID           string                           `json:"id"`
	Class        string                           `json:"class"`
	KeyCustody   string                           `json:"keyCustody"`
	ArtifactName string                           `json:"artifactName"`
	SHA256       string                           `json:"sha256"`
	SizeBytes    int64                            `json:"sizeBytes"`
	Chain        *componentrelease.ChainAuthority `json:"chain,omitempty"`
}
type classPrepareRequest struct {
	Schema  string            `json:"schema"`
	StoreID string            `json:"storeId"`
	Rows    []classPrepareRow `json:"rows"`
}
type signedClassRow struct {
	ID         string `json:"id"`
	Class      string `json:"class"`
	KeyCustody string `json:"keyCustody"`
	DeclaredAt string `json:"declaredAt"`
	Source     string `json:"source"`
}
type signedClassTable struct {
	Schema            string           `json:"schema"`
	StoreID           string           `json:"storeId"`
	OperatorPubkey    string           `json:"operatorPubkey"`
	SignedAtUnix      int64            `json:"signedAtUnix"`
	Rows              []signedClassRow `json:"rows"`
	OperatorSignature string           `json:"operatorSignature"`
}

func classField(dst []byte, value string) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}

func classTableMessage(t signedClassTable) []byte {
	content := append([]byte(nil), classDomain...)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(t.Rows)))
	content = append(content, count[:]...)
	for _, row := range t.Rows {
		b := append([]byte(nil), classDomain...)
		for _, field := range []string{row.ID, row.Class, row.KeyCustody, row.DeclaredAt, row.Source} {
			b = classField(b, field)
		}
		h := sha256.Sum256(b)
		content = append(content, h[:]...)
	}
	ch := sha256.Sum256(content)
	message := append([]byte(nil), classDomain...)
	for _, field := range []string{t.Schema, t.StoreID, t.OperatorPubkey} {
		message = classField(message, field)
	}
	var at [8]byte
	binary.BigEndian.PutUint64(at[:], uint64(t.SignedAtUnix))
	message = append(message, at[:]...)
	return append(message, ch[:]...)
}

func verifyPreparedClassTable(raw []byte, request classPrepareRequest, hashHex string, public ed25519.PublicKey, now time.Time) (signedClassTable, error) {
	var table signedClassTable
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&table) != nil || dec.Decode(new(json.RawMessage)) != io.EOF ||
		table.Schema != "melusina.sidecar-classes.v1" || table.StoreID != request.StoreID ||
		table.OperatorPubkey != primitives.EncodeBase58(public) ||
		table.SignedAtUnix < now.Add(-5*time.Minute).Unix() || table.SignedAtUnix > now.Add(time.Minute).Unix() ||
		len(table.Rows) != len(request.Rows) {
		return table, errors.New("prepared class table identity or shape mismatch")
	}
	for i, row := range table.Rows {
		want := request.Rows[i]
		wantID := request.Rows[i].ID
		if row.ID != wantID || row.Class != want.Class || row.KeyCustody != want.KeyCustody ||
			row.Source != "staged:"+hashHex || row.DeclaredAt != time.Unix(table.SignedAtUnix, 0).UTC().Format(time.RFC3339) {
			return table, fmt.Errorf("prepared class row mismatch: %s", wantID)
		}
	}
	sig, err := primitives.DecodeBase58(table.OperatorSignature)
	if err != nil || !ed25519.Verify(public, classTableMessage(table), sig) {
		return table, errors.New("prepared class table operator signature invalid")
	}
	return table, nil
}

func privateClassTransport(storeURL, connectAddress, leafPath string, timeout time.Duration) (*http.Client, error) {
	return publishclient.NewClient(storeURL, connectAddress, leafPath, timeout)
}

func runPrepareSidecarClasses(o options, requestBytes []byte, stdout io.Writer) error {
	if o.timeout > 20*time.Minute {
		return errors.New("class-table-prepare timeout exceeds 20 minutes")
	}
	var request classPrepareRequest
	dec := json.NewDecoder(bytes.NewReader(requestBytes))
	dec.DisallowUnknownFields()
	if dec.Decode(&request) != nil || dec.Decode(new(json.RawMessage)) != io.EOF ||
		(request.Schema != "melusina.sidecar-classes-prepare.v1" && request.Schema != "melusina.sidecar-classes-parent-prepare.v1") || request.StoreID != o.storeID ||
		len(request.Rows) < 1 || len(request.Rows) > 32 {
		return errors.New("class-table request preflight refused")
	}
	publisher, err := loadPublisherKey(o.publisherKey)
	if err != nil {
		return fmt.Errorf("publisher key: %w", err)
	}
	destination, err := loadStorePubkey(o.storePubkey)
	if err != nil {
		return fmt.Errorf("store pubkey: %w", err)
	}
	if keyProgram := publisher.Public().Ref.ProgramID; keyProgram != "" && keyProgram != o.programID {
		return errors.New("class-table publisher program differs from signed estate")
	}
	storePublic, err := destination.SignPublicKey()
	if err != nil {
		return err
	}
	hash := sha256.Sum256(requestBytes)
	hashHex := hex.EncodeToString(hash[:])
	ttl := o.timeout + 2*time.Minute
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	signed, err := envelope.Sign(envelope.KindPublishRequest, publisher, destination, envelope.SignOptions{
		Method: http.MethodPost, Target: classPreparePath, Body: requestBytes,
		BodyHash: hashHex, RequestHash: hashHex, TTL: ttl,
		Chain: envelope.ChainEvidence{ChainID: publisher.Public().Ref.ChainID,
			ProgramID: o.programID, VerifiedSlot: o.verifiedSlot},
	})
	if err != nil {
		return fmt.Errorf("sign class-table request: %w", err)
	}
	envelopeRaw, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(generationPromoteBody{Envelope: signed, RequestB64: base64.StdEncoding.EncodeToString(requestBytes)})
	if err != nil {
		return err
	}
	client, err := privateClassTransport(o.store, o.connectAddress, o.tlsLeaf, o.timeout)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.store, "/")+classPreparePath, bytes.NewReader(wire))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Melusina-Publisher-Envelope", base64.RawURLEncoding.EncodeToString(envelopeRaw))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("class-table Store POST: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBytes+1))
	if err != nil || len(raw) > maxRequestBytes {
		return errors.New("class-table Store response oversized or unreadable")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("class-table Store refused: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if _, err := verifyPreparedClassTable(raw, request, hashHex, storePublic, time.Now()); err != nil {
		return err
	}
	if err := atomicWrite(o.classTableOut, raw); err != nil {
		return fmt.Errorf("write class table: %w", err)
	}
	return json.NewEncoder(stdout).Encode(map[string]any{"status": "STORE_SIGNED_SIDECAR_CLASSES_OK",
		"rows": len(request.Rows), "requestSha256": hashHex,
		"classTableSha256": hex.EncodeToString(sha256SumClass(raw)), "classTablePath": o.classTableOut})
}

func sha256SumClass(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}
