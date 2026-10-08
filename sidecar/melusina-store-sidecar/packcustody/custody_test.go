package packcustody

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildSignedPack uses independent source keys for every service. The test
// producer signs the actual wire preimages, so the custody check cannot pass
// on a caller-supplied verdict or on unsigned fixture bytes.
func buildSignedPack(t *testing.T) ([]byte, map[string]ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	keys := map[string]ed25519.PrivateKey{}
	pins := map[string]ed25519.PublicKey{}
	for _, owner := range []string{"dueprocess", "namedcoin", "cyberteller", "ccash", "cca", "storage"} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[owner] = private
		pins[owner+"/test"] = public
	}
	const caseRef = "case-A"
	const testerRef = "tester-A"
	const correlationRef = "corr-A"
	memberBody := canonical(map[string]any{"case_ref": caseRef, "tester_ref": testerRef, "correlation_ref": correlationRef,
		"subject_digest": subject(caseRef, testerRef, correlationRef)})
	sum := sha256.Sum256(memberBody)
	memberHash := hex.EncodeToString(sum[:])
	descriptors := make([]descriptor, 0, len(roster))
	for _, name := range roster {
		owner := sources[name]
		preimage := append([]byte(nil), memberDomain...)
		preimage = binary.BigEndian.AppendUint16(preimage, uint16(len(name)))
		preimage = append(preimage, name...)
		preimage = append(preimage, sum[:]...)
		preimage = binary.BigEndian.AppendUint16(preimage, uint16(len(correlationRef)))
		preimage = append(preimage, correlationRef...)
		descriptors = append(descriptors, descriptor{Name: name, Size: uint64(len(memberBody)), SHA256: memberHash,
			IssuerKeyID: "test", IssuerSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(keys[owner], preimage))})
	}
	header := manifest{Version: "dueprocess-evidence-pack/1", CorrelationRef: correlationRef, CaseRef: caseRef,
		CreatedAt: "2026-10-08T00:00:00Z", SignerKeyID: "test",
		SignerPublicKey: base64.RawURLEncoding.EncodeToString(pins["dueprocess/test"]), Members: descriptors}
	manifestBytes := canonical(header)
	var pack bytes.Buffer
	pack.WriteString(magic)
	if err := binary.Write(&pack, binary.BigEndian, uint32(len(manifestBytes))); err != nil {
		t.Fatal(err)
	}
	pack.Write(manifestBytes)
	for _, desc := range descriptors {
		if err := binary.Write(&pack, binary.BigEndian, uint16(len(desc.Name))); err != nil {
			t.Fatal(err)
		}
		pack.WriteString(desc.Name)
		if err := binary.Write(&pack, binary.BigEndian, desc.Size); err != nil {
			t.Fatal(err)
		}
		pack.Write(memberBody)
	}
	signingPreimage := append([]byte(nil), packDomain...)
	signingPreimage = binary.BigEndian.AppendUint32(signingPreimage, uint32(len(manifestBytes)))
	signingPreimage = append(signingPreimage, manifestBytes...)
	pack.Write(ed25519.Sign(keys["dueprocess"], signingPreimage))
	return pack.Bytes(), pins, keys["dueprocess"]
}

func TestSignedPackCustodyPrivateTransport(t *testing.T) {
	pack, pins, signer := buildSignedPack(t)
	parent := t.TempDir()
	pearl := filepath.Join(parent, "grain")
	if err := os.Mkdir(pearl, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(parent, "retained"), pearl, pins)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(store.Handler())
	defer server.Close()
	put := func(body []byte) *http.Response {
		request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/pack/case-A/tester-A/corr-A", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	response := put(pack)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("signed pack transport positive: %d", response.StatusCode)
	}
	response.Body.Close()
	claim, err := SignReadClaim("case-A", "tester-A", "corr-A", "test", signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/pack/read", bytes.NewReader(canonical(claim)))
	if err != nil {
		t.Fatal(err)
	}
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	read, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(read, pack) || response.Header.Get("X-Evidence-Pack-SHA256") == "" {
		t.Fatalf("signed pack read transport positive: status=%d error=%v", response.StatusCode, err)
	}
	changed := append([]byte(nil), pack...)
	changed[len(changed)-1] ^= 1
	response = put(changed)
	refusal, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusConflict || !bytes.Contains(refusal, []byte("pack-tamper")) {
		t.Fatalf("pack-tamper: altered pack admitted on custody transport: status=%d error=%v", response.StatusCode, err)
	}
}

func TestSignedPackCustodyRetainsAndRefusesForeignTesterAndTamper(t *testing.T) {
	pack, pins, signer := buildSignedPack(t)
	otherPublic, otherSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pins["dueprocess/other-station"] = otherPublic
	parent := t.TempDir()
	pearl := filepath.Join(parent, "grain")
	if err := os.Mkdir(pearl, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(parent, "retained"), pearl, pins)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(pearl, "wrong"), pearl, pins); err == nil || !strings.Contains(err.Error(), "inside-pearl") {
		t.Fatalf("evidence-pack-custody-inside-pearl: %v", err)
	}
	value, err := store.Put(pack, "case-A", "tester-A", "corr-A")
	if err != nil {
		t.Fatalf("signed pack positive: %v", err)
	}
	if value == "" {
		t.Fatal("signed pack digest absent")
	}
	now := time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC)
	claim, err := SignReadClaim("case-A", "tester-A", "corr-A", "test", signer, now)
	if err != nil {
		t.Fatal(err)
	}
	read, digest, err := store.Read(claim, now)
	if err != nil || !bytes.Equal(read, pack) || digest != value {
		t.Fatalf("signed retained read positive: %v", err)
	}
	if _, err := store.Put(pack, "case-A", "tester-B", "corr-A"); err == nil || !strings.Contains(err.Error(), "pack-cross-tester") {
		t.Fatalf("pack-cross-tester: signed foreign tester admitted: %v", err)
	}
	foreign, err := SignReadClaim("case-A", "tester-B", "corr-A", "test", signer, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Read(foreign, now); err == nil || !strings.Contains(err.Error(), "pack-cross-tester") {
		t.Fatalf("pack-cross-tester: foreign signed read admitted: %v", err)
	}
	other, err := SignReadClaim("case-A", "tester-A", "corr-A", "other-station", otherSigner, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Read(other, now); err == nil || !strings.Contains(err.Error(), "pack-cross-tester") {
		t.Fatalf("pack-cross-tester: other Station key read admitted: %v", err)
	}
	changed := append([]byte(nil), pack...)
	changed[len(changed)-1] ^= 1
	if _, err := store.Put(changed, "case-A", "tester-A", "corr-A"); err == nil || !strings.Contains(err.Error(), "pack-tamper") {
		t.Fatalf("pack-tamper: changed signed bytes admitted: %v", err)
	}
	objectPath := filepath.Join(store.root, value+".pack")
	if err := os.WriteFile(objectPath, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Read(claim, now); err == nil || !strings.Contains(err.Error(), "pack-tamper: retained-digest-drift") {
		t.Fatalf("pack-tamper: changed retained object served: %v", err)
	}
	if _, _, err := store.Read(claim, now.Add(2*time.Minute)); err == nil || !strings.Contains(err.Error(), "read-claim-expired") {
		t.Fatalf("expired read claim accepted: %v", err)
	}
}
