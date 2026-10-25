package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
)

func TestClassTableEnvelopeOutIsRouteBoundOffline(t *testing.T) {
	dir := t.TempDir()
	var publisherSign, publisherBox, storeSign, storeBox [32]byte
	for i := range publisherSign {
		publisherSign[i] = 0x11
		publisherBox[i] = 0x22
		storeSign[i] = 0x33
		storeBox[i] = 0x44
	}
	pubRef := identity.Ref{Kind: identity.KindPearl, ChainID: testChainID, ProgramID: testProgramID, LicenseMint: "publisher-license", Domain: "publisher.example", PDA: "publisher-pda", PearlIDHash: strings.Repeat("a", 64), KeyVersion: 1}
	storeRef := identity.Ref{Kind: identity.KindSidecar, ChainID: testChainID, ProgramID: testProgramID, LicenseMint: "store-license", Domain: "store.example", PDA: "store-pda", SidecarID: "rrs-store", KeyVersion: 1}
	store, err := identity.NewPrivate(storeRef, storeSign, storeBox)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "publisher.json")
	storePath := filepath.Join(dir, "store.json")
	requestPath := filepath.Join(dir, "request.json")
	out := filepath.Join(dir, "signed.json")
	write := func(path string, value any) {
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(pubPath, publisherKeyFile{Ref: pubRef, SignSeed: hex.EncodeToString(publisherSign[:]), BoxSeed: hex.EncodeToString(publisherBox[:])})
	write(storePath, store.Public())
	request := []byte(`{"schema":"melusina.sidecar-classes-parent-prepare.v1","storeId":"rrs-store","rows":[{"id":"parent","class":"data","keyCustody":"none"}]}`)
	if err = os.WriteFile(requestPath, request, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--store", "https://127.0.0.1:1", "--store-id", "rrs-store", "--request", requestPath, "--publisher-key", pubPath, "--store-pubkey", storePath, "--program-id", testProgramID, "--timeout", "1ms", "--class-table-prepare", "--envelope-out", out}
	var stdout bytes.Buffer
	if err = run(args, &stdout); err != nil {
		t.Fatalf("offline parent envelope: %v", err)
	}
	if !strings.Contains(stdout.String(), "SIGNED_SIDECAR_CLASSES_ENVELOPE_OK") {
		t.Fatal(stdout.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var body generationPromoteBody
	if err = json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.Envelope.Payload.Method != http.MethodPost || body.Envelope.Payload.Target != classPreparePath {
		t.Fatalf("wrong route: %#v", body.Envelope.Payload)
	}
	got, err := base64.StdEncoding.DecodeString(body.RequestB64)
	if err != nil || !bytes.Equal(got, request) {
		t.Fatal("request binding changed")
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private envelope mode: %v %v", info, err)
	}
	if err = run(append(args, "--class-table-out", filepath.Join(dir, "table.json")), &bytes.Buffer{}); err == nil {
		t.Fatal("dual offline/live outputs accepted")
	}
}
