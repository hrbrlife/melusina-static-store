package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hrbrlife/melusina-attest/envelope"
)

func TestPrepareInstallerExportsOriginalSignedWireWithoutContactingStore(t *testing.T) {
	publisher, signSeed, boxSeed := testPrivate(t, "publisher")
	operator, _, _ := testPrivate(t, "store")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	dir := t.TempDir()
	artifact := []byte("closed original test artifact\x00\xff")
	sum := sha256.Sum256(artifact)
	publisherRaw, _ := json.Marshal(publisherKeyFile{Ref: publisher.Public().Ref, SignSeed: hex.EncodeToString(signSeed[:]), BoxSeed: hex.EncodeToString(boxSeed[:])})
	operatorRaw, _ := json.Marshal(operator.Public())
	for name, raw := range map[string][]byte{"artifact.bin": artifact, "publisher.json": publisherRaw, "operator.json": operatorRaw} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(dir, "prepared.json")
	args := []string{"--store", server.URL, "--class", "sidecar", "--name", "original.bin", "--artifact", filepath.Join(dir, "artifact.bin"), "--publisher-key", filepath.Join(dir, "publisher.json"), "--store-pubkey", filepath.Join(dir, "operator.json"), "--verified-slot", "123", "--prepare-out", output}
	var stdout bytes.Buffer
	if err := run(args, &stdout); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("preparation contacted Store")
	}
	st, err := os.Stat(output)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("prepared custody: %v %v", st, err)
	}
	raw, _ := os.ReadFile(output)
	var prepared struct {
		Schema, Store, Method, Target, Class, Name, ContentType string
		ArtifactSHA256                                          string `json:"artifactSha256"`
		ArtifactBytes                                           int    `json:"artifactBytes"`
		Body                                                    []byte `json:"bodyBase64"`
	}
	if err := json.Unmarshal(raw, &prepared); err != nil {
		t.Fatal(err)
	}
	if prepared.Schema != "melusina-installer-publish-prepared-v1" || prepared.Store != server.URL || prepared.Method != "POST" || prepared.Target != "/publish/installer" || prepared.Class != "sidecar" || prepared.Name != "original.bin" || prepared.ArtifactSHA256 != hex.EncodeToString(sum[:]) || prepared.ArtifactBytes != len(artifact) {
		t.Fatal("prepared exact descriptor mismatch")
	}
	r := httptest.NewRequest(prepared.Method, prepared.Target, bytes.NewReader(prepared.Body))
	r.Header.Set("Content-Type", prepared.ContentType)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		t.Fatal(err)
	}
	defer r.MultipartForm.RemoveAll()
	if r.FormValue("class") != prepared.Class || r.FormValue("name") != prepared.Name {
		t.Fatal("multipart target differs")
	}
	f, _, err := r.FormFile("artifact")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(f)
	f.Close()
	if !bytes.Equal(body, artifact) {
		t.Fatal("artifact bytes differ")
	}
	f, _, err = r.FormFile("envelope")
	if err != nil {
		t.Fatal(err)
	}
	var signed envelope.Signed
	err = json.NewDecoder(f).Decode(&signed)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.Verify(signed, envelope.VerifyOptions{ExpectedKind: envelope.KindPublishRequest, ExpectedSignerPubkeyB58: publisher.Public().SignPubkeyB58, ExpectedDestination: ptrPublic(operator.Public()), ExpectedRequestHash: prepared.ArtifactSHA256, NonceCache: envelope.NewMemoryNonceCache()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"storeContacted":false`) || !strings.Contains(stdout.String(), `"PREPARED_ONLY"`) {
		t.Fatal("output claims publication")
	}
	if err := run(args, io.Discard); err == nil {
		t.Fatal("overwrote existing preparation")
	}
	after, _ := os.ReadFile(output)
	if !bytes.Equal(raw, after) || calls.Load() != 0 {
		t.Fatal("refusal changed prior preparation or contacted Store")
	}
	args[len(args)-1] = "relative.json"
	if err := run(args, io.Discard); err == nil {
		t.Fatal("accepted relative output")
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(output, link); err != nil {
		t.Fatal(err)
	}
	args[len(args)-1] = link
	if err := run(args, io.Discard); err == nil {
		t.Fatal("followed output symlink")
	}
}
