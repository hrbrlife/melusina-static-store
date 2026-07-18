package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func TestDecodeRequestRejectsAmbiguousOrIncompleteInput(t *testing.T) {
	valid := []byte(`{"schema":"melusina-generation-promote-v1","channel":"stable","expectedCurrentGeneration":0,"components":[{}]}`)
	if _, err := decodeRequest(valid); err != nil {
		t.Fatalf("valid request preflight rejected: %v", err)
	}
	for name, raw := range map[string][]byte{
		"duplicate": []byte(`{"schema":"melusina-generation-promote-v1","schema":"melusina-generation-promote-v1","channel":"stable","components":[{}]}`),
		"unknown":   []byte(`{"schema":"melusina-generation-promote-v1","channel":"stable","components":[{}],"hostAction":"systemctl restart"}`),
		"trailing":  []byte(`{"schema":"melusina-generation-promote-v1","channel":"stable","components":[{}]} {}`),
		"empty":     []byte(`{"schema":"melusina-generation-promote-v1","channel":"","components":[]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRequest(raw); err == nil {
				t.Fatalf("accepted %s request", name)
			}
		})
	}
}

func TestPostPromoteUsesOnlyTheRouteBoundEnvelope(t *testing.T) {
	requestBytes := []byte(`{"schema":"melusina-generation-promote-v1","channel":"stable","components":[{}]}`)
	seen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = true
		if r.Method != http.MethodPost || r.URL.Path != generationPromoteTarget {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body generationPromoteBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Envelope.Payload.Method != http.MethodPost || body.Envelope.Payload.Target != generationPromoteTarget {
			t.Fatalf("wrong signed purpose: %#v", body.Envelope.Payload)
		}
		got, err := base64.StdEncoding.DecodeString(body.RequestB64)
		if err != nil || string(got) != string(requestBytes) {
			t.Fatalf("wire request did not preserve exact signed bytes: %q / %v", got, err)
		}
		_ = json.NewEncoder(w).Encode(generationPromoteResult{GenerationID: 9, PreviousGeneration: 8, GenerationHash: strings.Repeat("a", 64), ServedSHA256: strings.Repeat("b", 64), Path: "/update/generation.json"})
	}))
	defer server.Close()

	signed := envelope.Signed{}
	signed.Payload.Method = http.MethodPost
	signed.Payload.Target = generationPromoteTarget
	client := &http.Client{Timeout: time.Second}
	result, err := postPromote(context.Background(), client, server.URL, signed, requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !seen || result.GenerationID != 9 || result.Path != "/update/generation.json" {
		t.Fatalf("unexpected result: %#v", result)
	}

	signed.Payload.Target = "/publish"
	if _, err := postPromote(context.Background(), client, server.URL, signed, requestBytes); err == nil {
		t.Fatal("sent a cross-route envelope")
	}
}

func TestEnvelopeOutIsExactRouteBoundWireBodyAndDoesNotContactStore(t *testing.T) {
	tmp := t.TempDir()
	var publisherSign, publisherBox, storeSign, storeBox [32]byte
	for i := range publisherSign {
		publisherSign[i] = 0x11
		publisherBox[i] = 0x22
		storeSign[i] = 0x33
		storeBox[i] = 0x44
	}
	publisherRef := identity.Ref{
		Kind: identity.KindPearl, ChainID: defaultChainID, ProgramID: defaultProgramID,
		LicenseMint: "publisher-license", Domain: "publisher.example", PDA: "publisher-pda",
		PearlIDHash: strings.Repeat("a", 64), KeyVersion: 1,
	}
	publisher, err := identity.NewPrivate(publisherRef, publisherSign, publisherBox)
	if err != nil {
		t.Fatal(err)
	}
	publisherPath := filepath.Join(tmp, "publisher.json")
	publisherRaw, err := json.Marshal(publisherKeyFile{
		Ref: publisherRef, SignSeed: hex.EncodeToString(publisherSign[:]), BoxSeed: hex.EncodeToString(publisherBox[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publisherPath, publisherRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	storeRef := identity.Ref{
		Kind: identity.KindSidecar, ChainID: defaultChainID, ProgramID: defaultProgramID,
		LicenseMint: "store-license", Domain: "store.example", PDA: "store-pda", SidecarID: "rrs-store", KeyVersion: 1,
	}
	store, err := identity.NewPrivate(storeRef, storeSign, storeBox)
	if err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(tmp, "store-public.json")
	storeRaw, err := json.Marshal(store.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storePath, storeRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	request := []byte(`{"schema":"melusina-generation-promote-v1","channel":"stable","expectedCurrentGeneration":0,"components":[{}]}`)
	requestPath := filepath.Join(tmp, "request.json")
	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(tmp, "out", "signed-generation.json")
	var stdout bytes.Buffer
	// Deliberately unreachable: envelope-out must return before it attempts any
	// HTTP request. The exact bound body is for a later authorized target POST.
	err = run([]string{
		"--store", "https://127.0.0.1:1", "--store-id", "rrs-store", "--request", requestPath,
		"--publisher-key", publisherPath, "--store-pubkey", storePath, "--timeout", "1ms",
		"--envelope-out", envelopePath,
	}, &stdout)
	if err != nil {
		t.Fatalf("offline envelope output: %v", err)
	}
	var body generationPromoteBody
	got, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatal(err)
	}
	if body.Envelope.Payload.Method != http.MethodPost || body.Envelope.Payload.Target != generationPromoteTarget {
		t.Fatalf("offline body lost route binding: %#v", body.Envelope.Payload)
	}
	if body.Envelope.Payload.Source.Digest() != publisher.Public().Digest() || body.Envelope.Payload.Destination.Digest() != store.Public().Digest() {
		t.Fatal("offline body bound the wrong publisher or store identity")
	}
	decoded, err := base64.StdEncoding.DecodeString(body.RequestB64)
	if err != nil || !bytes.Equal(decoded, request) {
		t.Fatalf("offline body did not preserve exact request bytes: %q / %v", decoded, err)
	}
	if info, err := os.Stat(envelopePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("signed envelope must be atomically private: mode=%v err=%v", func() os.FileMode {
			if info == nil {
				return 0
			}
			return info.Mode().Perm()
		}(), err)
	}
	if !strings.Contains(stdout.String(), "SIGNED_GENERATION_ENVELOPE_OK") {
		t.Fatalf("unexpected offline result: %s", stdout.String())
	}
}

func TestFetchAndVerifyGenerationPinsSignerAndStoreID(t *testing.T) {
	var signSeed, boxSeed [32]byte
	for i := range signSeed {
		signSeed[i] = 0x31
		boxSeed[i] = 0x42
	}
	operator, err := identity.NewPrivate(identity.Ref{
		Kind: identity.KindSidecar, ChainID: "solana:devnet", ProgramID: defaultProgramID,
		LicenseMint: "license", Domain: "store.example", PDA: "operator-pda", SidecarID: "store",
	}, signSeed, boxSeed)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := componentrelease.Sign(operator, componentrelease.DesiredGeneration{
		GenerationID: 1, StoreID: "store-1", BundleOrigin: "https://store.example", Channel: "stable", SignedAtUnix: 1,
		Components: []componentrelease.ComponentRelease{{
			ComponentID: "shell", ComponentClass: componentrelease.ClassShell, Version: "build-1", ArtifactName: "shell.bin",
			SHA256: strings.Repeat("a", 64), SizeBytes: 1, BundleURL: "https://store.example/releases/shell/shell.bin",
			Chain: componentrelease.ChainAuthority{Kind: componentrelease.AuthorityInstallerRelease, Program: defaultProgramID, MasterNftMint: "master", ReleasePDA: "release"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/update/generation.json" {
			t.Fatalf("unexpected read-back %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	key, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	gotRaw, got, err := fetchAndVerifyGeneration(context.Background(), &http.Client{Timeout: time.Second}, server.URL, "store-1", key)
	if err != nil || string(gotRaw) != string(raw) || got.GenerationHash != doc.GenerationHash {
		t.Fatalf("valid signed read-back rejected: doc=%#v err=%v", got, err)
	}
	if _, _, err := fetchAndVerifyGeneration(context.Background(), &http.Client{Timeout: time.Second}, server.URL, "foreign-store", key); err == nil {
		t.Fatal("accepted generation for a foreign store ID")
	}
}
