package main

// Hermetic state-machine test fixture for the mel-release CLI (Wave-1 exit gate).
//
// Everything external is FAKED, in-process, no live chain/store/infra:
//   - the SignerProvider is a tiny stdlib-only Go program compiled once to a temp
//     dir and pointed at by MEL_RELEASE_SIGNER_PROVIDER. It emits deterministic
//     canned receipts and maintains a fake-chain state file (active releases,
//     served appHash, per-PDA status, ReleaseEntry account bytes) that mutates
//     exactly where the real chain would (promote sets served, revoke flips to
//     Revoked in the status and in the account bytes). It never registers a
//     ReleaseEntry: the harness plays the owner-authorized runner
//     (runnerRegister), which writes the program-layout account.
//   - the store is an httptest.Server implementing /publish/generation (fold +
//     operator-sign a single-component DesiredGeneration) and GET
//     /update/generation.json, returning documents the CLI's own
//     componentrelease.Verify accepts (operator-signed with a test key whose
//     Public JSON the fake also advertises via MEL_RELEASE_STORE_PUBKEY).
//   - MEL_RELEASE_STATE_DIR is a per-test temp dir for the WAL.
//
// The test is package main, so it drives runPublish/runApprove directly (bypassing
// loadConfig's bare-https assertion, which lets the store live on an http httptest
// origin while the component bundleUrls remain the pinned https bazaar origin the
// componentrelease validator requires).

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// ── the fake signer provider (compiled once) ────────────────────────────────────

const fakeProviderSrc = `package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Ref struct{ PDA, AppHash, Version string }
type Version struct {
	AppHash, PkgID, MasterMint, SpkPath, MetadataPath, ArtifactSha string
	RuntimeContractPath, RuntimeContractSHA256                     string
	ArtifactSize, RuntimeContractSize                              int64
	PdaNew, PreviousSha256, PreviousVersion                        string
}
type Fixture struct {
	TransactionPda, StageID string
	Versions                map[string]Version
	InitialActive           []Ref
	InitialServed           string
	InitialStatuses         map[string]string
}
type Inflight struct{ Version, AppHash, PdaNew, ReleaseHash string }
type Account struct{ Owner, Data string }
type Finalize struct {
	AuthorSig, Master, Vault string
	RegisteredAt             int64
}
type State struct {
	Active      []Ref
	Served      string
	Statuses    map[string]string
	ReleaseHash map[string]string
	Inflight    map[string]Inflight
	Accounts    map[string]Account
	Finalize    map[string]Finalize
	Seeded      bool
}

// recallAccount is revoke_release_entry on the stored bytes: status Revoked
// and revoked_at Some(at), with bump moved after the Option payload.
func recallAccount(data string, at int64) string {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil || len(raw) < 140 {
		die("stored ReleaseEntry is not an account")
	}
	status := 140 + int(binary.LittleEndian.Uint32(raw[136:140])) + 32 + 32 + 64 + 32 + 32 + 8
	if status+11 > len(raw) || raw[status+1] != 0 {
		return data
	}
	bump := raw[status+2]
	raw[status] = 1
	raw[status+1] = 1
	binary.LittleEndian.PutUint64(raw[status+2:], uint64(at))
	raw[status+10] = bump
	return base64.StdEncoding.EncodeToString(raw)
}

func env(k string) string { return os.Getenv(k) }
func die(m string)        { fmt.Fprintln(os.Stderr, "fakeprovider:", m); os.Exit(1) }

func readJSON(path string, dst any) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		die("parse " + path + ": " + err.Error())
	}
	return true
}
func writeJSON(path string, v any) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		die(err.Error())
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		die(err.Error())
	}
}
func appendLine(path, line string) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		die(err.Error())
	}
	defer f.Close()
	f.WriteString(line + "\n")
}

func main() {
	if len(os.Args) < 2 {
		die("usage: fakeprovider <op>")
	}
	op := os.Args[1]
	appendLine(env("MEL_FAKE_CALLLOG"), op)
	if f := env("MEL_FAKE_FAIL_OP"); f != "" && f == op {
		die("injected fault on op " + op)
	}
	var fx Fixture
	if !readJSON(env("MEL_FAKE_FIXTURE"), &fx) {
		die("no fixture")
	}
	statePath := env("MEL_FAKE_STATE")
	var st State
	dirty := false
	if !readJSON(statePath, &st) {
		st = State{
			Active: append([]Ref{}, fx.InitialActive...), Served: fx.InitialServed,
			Statuses: map[string]string{}, ReleaseHash: map[string]string{},
			Inflight: map[string]Inflight{}, Seeded: true,
		}
		for k, v := range fx.InitialStatuses {
			st.Statuses[k] = v
		}
		dirty = true
	}
	if st.Statuses == nil {
		st.Statuses = map[string]string{}
	}
	if st.ReleaseHash == nil {
		st.ReleaseHash = map[string]string{}
	}
	if st.Inflight == nil {
		st.Inflight = map[string]Inflight{}
	}
	if st.Accounts == nil {
		st.Accounts = map[string]Account{}
	}
	if st.Finalize == nil {
		st.Finalize = map[string]Finalize{}
	}

	lookup := func(pda string) (string, string, bool) {
		for _, r := range fx.InitialActive {
			if r.PDA == pda {
				return r.AppHash, r.Version, true
			}
		}
		for ver, v := range fx.Versions {
			if v.PdaNew == pda {
				return v.AppHash, ver, true
			}
		}
		for _, r := range st.Active {
			if r.PDA == pda {
				return r.AppHash, r.Version, true
			}
		}
		return "", "", false
	}
	snapshot := func() {
		pdas := []string{}
		for _, r := range st.Active {
			pdas = append(pdas, r.PDA)
		}
		line := strings.Join(pdas, ",")
		if line == "" {
			line = "EMPTY"
		}
		appendLine(env("MEL_FAKE_CHAINLOG"), line)
	}

	switch op {
	case "build":
		ver := env("MEL_NEW_VERSION")
		v, ok := fx.Versions[ver]
		if !ok {
			die("no fixture version " + ver)
		}
		rec := map[string]any{
			"schema":        "melusina-app-candidate-receipt-v1",
			"app":           map[string]any{"appId": env("MEL_APP_ID"), "version": ver},
			"artifact":      map[string]any{"sha256": v.ArtifactSha, "size": v.ArtifactSize},
			"appHash":       v.AppHash,
			"packageId":     v.PkgID,
			"masterNftMint": v.MasterMint,
			"spkPath":       v.SpkPath,
			"metadataPath":  v.MetadataPath,
			"runtimeContract": map[string]any{"sha256": v.RuntimeContractSHA256, "size": v.RuntimeContractSize, "path": v.RuntimeContractPath},
		}
		if v.PreviousSha256 != "" {
			rec["previousSha256"] = v.PreviousSha256
			rec["previousVersion"] = v.PreviousVersion
		}
		writeJSON(env("MEL_CANDIDATE_RECEIPT_OUT"), rec)

	case "active-releases":
		if eq := env("MEL_FAKE_FAIL_ACTIVE_EQ"); eq != "" && len(st.Active) == 1 && st.Active[0].PDA == eq {
			die("injected final-verify fault (single active == " + eq + ")")
		}
		var b strings.Builder
		for _, r := range st.Active {
			line, _ := json.Marshal(map[string]any{"pda": r.PDA, "appHash": r.AppHash, "version": r.Version})
			b.Write(line)
			b.WriteByte('\n')
		}
		fmt.Print(b.String())

	case "release-status":
		pda := env("MEL_PDA")
		ah, ver, ok := lookup(pda)
		if !ok {
			die("unknown pda " + pda)
		}
		status := st.Statuses[pda]
		if status == "" {
			status = "Active"
		}
		out, _ := json.Marshal(map[string]any{"pda": pda, "appHash": ah, "version": ver, "status": status})
		fmt.Println(string(out))

	case "served-app-hash":
		fmt.Print(st.Served)

	case "stage":
		writeJSON(env("MEL_STAGE_RECEIPT_OUT"), map[string]any{
			"schema": "melusina-app-stage-receipt-v1", "stageId": fx.StageID,
			"appId": env("MEL_APP_ID"), "appHash": env("MEL_NEW_APP_HASH"), "releaseHash": env("MEL_RELEASE_HASH"),
		})

	case "propose-register":
		app := env("MEL_APP_ID")
		appHash := env("MEL_NEW_APP_HASH")
		ver := env("MEL_NEW_VERSION")
		nonce := env("MEL_RELEASE_NONCE")
		sum := sha256.Sum256([]byte(appHash + ver + nonce))
		releaseHash := hex.EncodeToString(sum[:])
		v := fx.Versions[ver]
		st.ReleaseHash[ver] = releaseHash
		st.Inflight[app] = Inflight{Version: ver, AppHash: appHash, PdaNew: v.PdaNew, ReleaseHash: releaseHash}
		dirty = true
		writeJSON(env("MEL_RELEASE_JSON_OUT"), map[string]any{
			"$schema": "melusina-release-v1", "appHash": appHash, "releaseHash": releaseHash,
			"version": ver, "releaseNonce": nonce, "releaseEntryPda": v.PdaNew,
		})
		writeJSON(env("MEL_PROPOSE_RECEIPT_OUT"), map[string]any{
			"schema": "melusina-register-proposal-receipt-v1", "releaseEntryPda": v.PdaNew,
			"transactionPda": fx.TransactionPda, "multisig": env("MEL_SQUADS_MULTISIG"),
			"vault": env("MEL_SQUADS_VAULT"), "instruction": "register_release_entry", "status": "Proposed",
		})

	case "release-entry-account":
		pda := env("MEL_PDA")
		out := map[string]any{"pda": pda, "present": false}
		if a, ok := st.Accounts[pda]; ok {
			out = map[string]any{"pda": pda, "present": true, "owner": a.Owner, "dataBase64": a.Data}
		}
		line, _ := json.Marshal(out)
		fmt.Println(string(line))

	case "finalize-release":
		// Read-only on the fake chain: bind the provider's RELEASE.json to the
		// registered entry. It never registers anything.
		app := env("MEL_APP_ID")
		inf := st.Inflight[app]
		if inf.PdaNew == "" {
			die("no inflight candidate for " + app)
		}
		if env("MEL_NEW_APP_HASH") != inf.AppHash || env("MEL_RELEASE_HASH") != inf.ReleaseHash || env("MEL_NEW_VERSION") != inf.Version {
			die("finalize-release request does not bind the inflight candidate")
		}
		if _, ok := st.Accounts[inf.PdaNew]; !ok {
			die("release-entry-missing: no ReleaseEntry at " + inf.PdaNew)
		}
		f := st.Finalize[inf.PdaNew]
		threshold, _ := strconv.Atoi(env("MEL_RELEASE_SQUADS_THRESHOLD"))
		members, _ := strconv.Atoi(env("MEL_RELEASE_SQUADS_MEMBER_COUNT"))
		writeJSON(env("MEL_FINAL_RELEASE_JSON_OUT"), map[string]any{
			"$schema": "melusina-release-v1", "appHash": inf.AppHash, "releaseHash": inf.ReleaseHash,
			"version": inf.Version, "releaseNonce": env("MEL_RELEASE_NONCE"), "releaseEntryPda": inf.PdaNew,
			"signedAtUnix": f.RegisteredAt, "masterNftMint": f.Master, "licenseSquadsVault": f.Vault,
			"authorSig": f.AuthorSig,
			"quorumPolicy": map[string]any{"threshold": threshold, "memberCount": members, "multisigPda": env("MEL_RELEASE_SQUADS_MULTISIG")},
		})

	case "promote":
		appHash := env("MEL_NEW_APP_HASH")
		if st.Served != appHash {
			st.Served = appHash
			dirty = true
			snapshot()
		}
		writeJSON(env("MEL_PROMOTE_RECEIPT_OUT"), map[string]any{
			"schema": "melusina-app-promotion-receipt-v1", "appHash": appHash,
			"releaseHash": env("MEL_RELEASE_HASH"),
			"catalog": map[string]any{
				"appId": env("MEL_APP_ID"), "appHash": appHash, "releaseHash": env("MEL_RELEASE_HASH"),
				"stageId": env("MEL_STAGE_ID"), "version": env("MEL_NEW_VERSION"),
			},
		})

	case "revoke":
		pda := env("MEL_PDA")
		wasRevoked := st.Statuses[pda] == "Revoked"
		rec := map[string]any{"schema": "melusina-revoke-release-receipt-v1", "releaseEntryPda": pda, "status": "Revoked"}
		if wasRevoked {
			rec["alreadyRevoked"] = true
		} else {
			st.Statuses[pda] = "Revoked"
			if a, ok := st.Accounts[pda]; ok {
				a.Data = recallAccount(a.Data, 1790000999)
				st.Accounts[pda] = a
			}
			na := []Ref{}
			for _, r := range st.Active {
				if r.PDA != pda {
					na = append(na, r)
				}
			}
			st.Active = na
			dirty = true
			snapshot()
			rec["transactionSignature"] = "revsig-" + pda
		}
		writeJSON(env("MEL_REVOKE_RECEIPT_OUT"), rec)

	default:
		die("unknown op " + op)
	}

	if dirty {
		writeJSON(statePath, st)
	}
}
`

var (
	providerOnce sync.Once
	providerPath string
	providerErr  error
)

func fakeProviderBin(t *testing.T) string {
	t.Helper()
	providerOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mel-fakeprovider-")
		if err != nil {
			providerErr = err
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(fakeProviderSrc), 0o600); err != nil {
			providerErr = err
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fakeprovider\n\ngo 1.25\n"), 0o600); err != nil {
			providerErr = err
			return
		}
		bin := filepath.Join(dir, "fakeprovider")
		cmd := exec.Command("go", "build", "-o", bin, ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=", "GO111MODULE=on")
		if out, err := cmd.CombinedOutput(); err != nil {
			providerErr = fmt.Errorf("build fake provider: %v: %s", err, out)
			return
		}
		providerPath = bin
	})
	if providerErr != nil {
		t.Fatalf("fake provider: %v", providerErr)
	}
	return providerPath
}
