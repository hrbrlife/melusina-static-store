package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/squadsproof"
	primitives "github.com/melusina-os/melusina-solana-primitives"
	"net/http"
	"net/http/httptest"
)

type hostApplySDKFixture struct {
	ProgramID               string `json:"program_id"`
	MultisigAddress         string `json:"multisig_address"`
	VaultAddress            string `json:"vault_address"`
	ProposalAddress         string `json:"proposal_address"`
	VaultTransactionAddress string `json:"vault_transaction_address"`
	MemoPayload             string `json:"memo_payload"`
	MultisigDataHex         string `json:"multisig_data_hex"`
	ProposalDataHex         string `json:"proposal_data_hex"`
	VaultTransactionDataHex string `json:"vault_transaction_data_hex"`
}

type hostApplyPlanFixture struct {
	svc           *publishService
	chain         *mockChainReader
	component     componentrelease.ComponentRelease
	now           time.Time
	signature     string
	multisig      string
	vault         string
	proposal      string
	vaultTx       string
	proofMultisig []byte
	proofProposal []byte
	proofVaultTx  []byte
	operatorAuthz string
	storeLicense  string
	targetLicense string
}

func mkHostApplyLicenseAccount(license, reseller, master, vault, multisig primitives.Pubkey) []byte {
	b := accountDiscriminator("LicenseEntry")
	b = append(b, license[:]...)
	b = append(b, reseller[:]...)
	b = append(b, master[:]...)
	b = mkPutU64(b, 1)
	b = mkPutString(b, "acceptance.example")
	b = mkPutString(b, "https://acceptance.example/install")
	b = append(b, make([]byte, 32)...)
	b = append(b, 1, 1, 1)
	b = append(b, make([]byte, 32)...)
	b = append(b, 1) // Squads custody
	b = append(b, 1)
	b = append(b, vault[:]...)
	b = append(b, 1)
	b = append(b, multisig[:]...)
	b = append(b, 0) // Active
	b = mkPutU64(b, 1)
	b = append(b, 0)
	b = mkPutU32(b, 0)
	b = mkPutU32(b, 0)
	b = append(b, 0, 0)
	b = append(b, make([]byte, 32)...)
	b = append(b, 0)
	b = mkPutString(b, "")
	b = mkPutString(b, "")
	b = mkPutU32(b, 0)
	return b
}

func loadHostApplySDKFixture(t *testing.T) hostApplySDKFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "squadsproof", "squads-v4-memo-only.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out hostApplySDKFixture
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func mutateHostApplyMultisigIndex(t *testing.T, raw []byte, index uint64) []byte {
	t.Helper()
	out := append([]byte(nil), raw...)
	const transactionIndexOffset = 8 + 32 + 32 + 2 + 4
	if len(out) < transactionIndexOffset+8 {
		t.Fatal("SDK multisig fixture is truncated")
	}
	binary.LittleEndian.PutUint64(out[transactionIndexOffset:transactionIndexOffset+8], index)
	return out
}

func replaceHostApplyMemo(t *testing.T, raw []byte, oldMemo, newMemo string) []byte {
	t.Helper()
	position := bytes.LastIndex(raw, []byte(oldMemo))
	if position < 4 || bytes.Count(raw, []byte(oldMemo)) != 1 {
		t.Fatal("SDK vault transaction fixture has no unique memo payload")
	}
	if binary.LittleEndian.Uint32(raw[position-4:position]) != uint32(len(oldMemo)) {
		t.Fatal("SDK vault transaction fixture memo length does not precede payload")
	}
	out := make([]byte, 0, len(raw)-len(oldMemo)+len(newMemo))
	out = append(out, raw[:position-4]...)
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(newMemo)))
	out = append(out, length[:]...)
	out = append(out, []byte(newMemo)...)
	out = append(out, raw[position+len(oldMemo):]...)
	return out
}

func newHostApplyPlanFixture(t *testing.T) hostApplyPlanFixture {
	t.Helper()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	cfg, _ := testConfig(t)
	cfg.ProgramID = programID.Base58()
	cfg.PublicBaseURL = "https://bazaar.melusina-os.org"
	cfg.PrivateStageDir = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = op.Public().SignPubkeyB58
	chain := newMockChainReader()
	license, err := primitives.PubkeyFromBase58(cfg.LicenseNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	targetLicense, err := primitives.PubkeyFromBase58(randPubkeyB58(t))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := primitives.PubkeyFromBase58(cfg.StoreAuthority)
	if err != nil {
		t.Fatal(err)
	}
	authz, _, err := pda.StoreOperatorAuthorization(license, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	operatorRaw := operatorSignPub32(t, op)
	chain.storeAuthz[authz.Base58()] = mockStoreAuthz{status: verify.AuthorizationStatusActive, authority: verify.Pubkey(operatorRaw), tierMask: 0xff, domainHash: primitives.StoreDomainHash(cfg.Domain)}
	policyPDA, err := deriveStoreControlPolicy(license, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	chain.rawAccounts[policyPDA.Base58()] = controlPolicyBlob(license, primitives.StoreDomainHash(cfg.Domain), authority, authz, [32]byte{9}, [32]byte{7}, 7)

	artifact := []byte("fineract-v2-governed-candidate")
	sum := sha256.Sum256(artifact)
	sha := hex.EncodeToString(sum[:])
	name := "fineract-sidecar-" + sha[:16] + ".bin"
	if err := os.MkdirAll(filepath.Join(cfg.DistDir, "releases", "sidecar"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "releases", "sidecar", name), artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	identityPDA, _, err := pda.SidecarIdentity(targetLicense, hostApplyFineractSidecarID, 1, programID)
	if err != nil {
		t.Fatal(err)
	}
	var master primitives.Pubkey
	master[0], master[1] = 0xBB, 0x02
	globalPDA, _, err := primitives.DeriveGlobalSidecar(master, hostApplyFineractSidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	localPDA, _, err := primitives.DeriveLocalSidecar(targetLicense, hostApplyFineractSidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	component := componentrelease.ComponentRelease{
		ComponentID: hostApplyFineractComponentID, ComponentClass: componentrelease.ClassSidecar,
		Version: "0.1.38-contract", Build: 1, ArtifactName: name, SHA256: sha, SizeBytes: int64(len(artifact)),
		BundleURL: cfg.PublicBaseURL + "/releases/sidecar/" + name, ReleaseHash: strings.Repeat("d", 64),
		StageID: strings.Repeat("e", 64), PreviousSHA256: strings.Repeat("f", 64), PreviousVersion: "0.1.37-contract",
		Chain: componentrelease.ChainAuthority{Kind: componentrelease.AuthoritySidecarIdentity, Program: programID.Base58(), LicenseNftMint: targetLicense.Base58(), MasterNftMint: testMaster, SidecarID: hostApplyFineractSidecarID, KeyVersion: 1, IdentityPDA: identityPDA.Base58(), GlobalApprovalPDA: globalPDA.Base58(), LocalApprovalPDA: localPDA.Base58()},
	}
	chain.sidecarIdentity[identityPDA.Base58()] = mockSidecarIdentity{sid: verify.SidecarIdentity{Status: verify.AttestationStatusActive, BinaryHash: sum}}
	seedValidCascade(t, chain, targetLicense, hostApplyFineractSidecarID, sum)

	doc := componentrelease.DesiredGeneration{GenerationID: 77, StoreID: cfg.StoreID, BundleOrigin: cfg.PublicBaseURL, Channel: "dev", SignedAtUnix: now.Add(-time.Minute).Unix(), PreviousGeneration: 76, Components: []componentrelease.ComponentRelease{component}}
	doc, err = componentrelease.Sign(op, doc)
	if err != nil {
		t.Fatal(err)
	}
	rawGeneration, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(cfg.DistDir, rawGeneration); err != nil {
		t.Fatal(err)
	}

	sdk := loadHostApplySDKFixture(t)
	multisig, err := primitives.PubkeyFromBase58(sdk.MultisigAddress)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := primitives.PubkeyFromBase58(sdk.VaultAddress)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := primitives.PubkeyFromBase58(sdk.ProposalAddress)
	if err != nil {
		t.Fatal(err)
	}
	vaultTx, err := primitives.PubkeyFromBase58(sdk.VaultTransactionAddress)
	if err != nil {
		t.Fatal(err)
	}
	proofMultisig, err := hex.DecodeString(sdk.MultisigDataHex)
	if err != nil {
		t.Fatal(err)
	}
	proofProposal, err := hex.DecodeString(sdk.ProposalDataHex)
	if err != nil {
		t.Fatal(err)
	}
	proofVaultTx, err := hex.DecodeString(sdk.VaultTransactionDataHex)
	if err != nil {
		t.Fatal(err)
	}
	chain.rawAccounts[multisig.Base58()] = mutateHostApplyMultisigIndex(t, proofMultisig, 6)
	chain.rawAccountOwners[multisig.Base58()] = squadsproof.DefaultProgramIDBase58
	chain.rawAccounts[proposal.Base58()] = proofProposal
	chain.rawAccountOwners[proposal.Base58()] = squadsproof.DefaultProgramIDBase58
	chain.rawAccounts[vaultTx.Base58()] = proofVaultTx
	chain.rawAccountOwners[vaultTx.Base58()] = squadsproof.DefaultProgramIDBase58
	licensePDA, _, err := primitives.DeriveLicense(targetLicense, programID)
	if err != nil {
		t.Fatal(err)
	}
	var reseller primitives.Pubkey
	reseller[0], reseller[1] = 0xAA, 0x01
	chain.rawAccounts[licensePDA.Base58()] = mkHostApplyLicenseAccount(targetLicense, reseller, master, vault, multisig)

	svc := newTestService(t, cfg, chain, op)
	svc.now = func() time.Time { return now }
	signature := primitives.EncodeBase58(bytes.Repeat([]byte{0x42}, 64))
	return hostApplyPlanFixture{svc: svc, chain: chain, component: component, now: now, signature: signature, multisig: multisig.Base58(), vault: vault.Base58(), proposal: proposal.Base58(), vaultTx: vaultTx.Base58(), proofMultisig: proofMultisig, proofProposal: proofProposal, proofVaultTx: proofVaultTx, operatorAuthz: authz.Base58(), storeLicense: license.Base58(), targetLicense: targetLicense.Base58()}
}

func hostApplyPlanRequest(t *testing.T, dossier string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, hostApplyIssuePathPrefix+dossier+hostApplyPlanPathSuffix, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func hostApplyProofHTTPReq(t *testing.T, dossier, digest, signature string) *http.Request {
	t.Helper()
	body, err := json.Marshal(hostApplyProofRequest{PlanDigest: digest, ExecutionSignature: signature})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, hostApplyIssuePathPrefix+dossier+hostApplyProofPathSuffix, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func (f hostApplyPlanFixture) armProof(t *testing.T, plan hostApplyPlan) {
	t.Helper()
	program := squadsproof.DefaultProgramID
	multisigKey, err := squadsproof.DecodePubkey(f.multisig)
	if err != nil {
		t.Fatal(err)
	}
	parsedMultisig, err := squadsproof.ParseMultisig(squadsproof.Account{Address: multisigKey, Owner: program, Data: f.proofMultisig}, program)
	if err != nil {
		t.Fatal(err)
	}
	vaultTxKey, err := squadsproof.DecodePubkey(f.vaultTx)
	if err != nil {
		t.Fatal(err)
	}
	parsedVaultTx, err := squadsproof.ParseVaultTransaction(squadsproof.Account{Address: vaultTxKey, Owner: program, Data: f.proofVaultTx}, program)
	if err != nil {
		t.Fatal(err)
	}
	creator := parsedVaultTx.Creator
	creatorInfo, ok := hostApplyCurrentMember(parsedMultisig, creator)
	if !ok || creatorInfo.Permissions&squadsproof.PermissionInitiate == 0 {
		t.Fatalf("SDK fixture creator %s is not initiate-capable: found=%t permissions=%08b", creator.Base58(), ok, creatorInfo.Permissions)
	}
	var member squadsproof.Pubkey
	for _, candidate := range parsedMultisig.Members {
		if candidate.Permissions&squadsproof.PermissionExecute != 0 {
			member = candidate.Key
			break
		}
	}
	if member == (squadsproof.Pubkey{}) {
		t.Fatal("SDK fixture has no execute-capable member")
	}
	f.chain.rawAccounts[f.multisig] = append([]byte(nil), f.proofMultisig...)
	f.chain.rawAccounts[f.vaultTx] = replaceHostApplyMemo(t, f.proofVaultTx, loadHostApplySDKFixture(t).MemoPayload, plan.Memo())
	f.chain.hostApplyTransactions[f.signature] = hostApplyFinalizedTransaction{
		Signature: f.signature, Signatures: []string{f.signature}, Slot: 100,
		Header: hostApplyTxHeader{NumRequiredSignatures: 1, NumReadonlySignedAccounts: 0, NumReadonlyUnsignedAccounts: 4},
		// Solana's canonical key ordering puts writable unsigned accounts before
		// readonly unsigned accounts: member, proposal, vault, then multisig,
		// vault transaction, memo and program.
		AccountKeys:       []string{member.Base58(), f.proposal, f.vault, f.multisig, f.vaultTx, squadsproof.DefaultMemoProgramIDBase58, squadsproof.DefaultProgramIDBase58},
		Instructions:      []hostApplyCompiledInstruction{{ProgramIDIndex: 6, Accounts: []uint8{3, 1, 4, 0, 2, 5}, Data: primitives.EncodeBase58([]byte{194, 8, 161, 87, 153, 164, 25, 171})}},
		InnerInstructions: []hostApplyInnerInstructionSet{{Index: 0, Instructions: []hostApplyCompiledInstruction{{ProgramIDIndex: 5, Accounts: []uint8{2}, Data: primitives.EncodeBase58([]byte(plan.Memo()))}}}},
	}
}

func TestHostApplyPlanIsPrivateAndProofBindsRealFinalizedSquadsExecution(t *testing.T) {
	f := newHostApplyPlanFixture(t)
	const dossier = "0123456789abcdef01234567"
	public := newPublicRouterWithService(f.svc.cfg, f.svc.operator, f.chain, nil, catalogRuntime{}, f.svc, true)
	private := newControlReleaseRouter(f.svc)

	publicResponse := httptest.NewRecorder()
	public.ServeHTTP(publicResponse, hostApplyPlanRequest(t, dossier))
	if publicResponse.Code != http.StatusNotFound {
		t.Fatalf("public plan route = %d: %s", publicResponse.Code, publicResponse.Body.String())
	}

	planResponse := httptest.NewRecorder()
	private.ServeHTTP(planResponse, hostApplyPlanRequest(t, dossier))
	if planResponse.Code != http.StatusOK {
		t.Fatalf("plan = %d: %s", planResponse.Code, planResponse.Body.String())
	}
	var planned hostApplyPlanResult
	if err := json.Unmarshal(planResponse.Body.Bytes(), &planned); err != nil {
		t.Fatal(err)
	}
	if planned.Schema != hostApplyPlanResultSchema || planned.PlanDigest != planned.Plan.Digest() || planned.Memo != planned.Plan.Memo() || planned.Plan.SquadsTransactionIndexFloor != 6 || planned.Plan.SquadsThreshold < 2 {
		t.Fatalf("invalid immutable plan: %+v", planned)
	}
	if planned.Plan.TargetLicenseNftMint != f.targetLicense || planned.Plan.TargetLicenseNftMint == f.storeLicense || planned.Plan.StoreOperatorAuthorization != f.operatorAuthz {
		t.Fatalf("plan conflated Store and tenant authority planes: %+v", planned.Plan)
	}
	f.armProof(t, planned.Plan)

	proofResponse := httptest.NewRecorder()
	private.ServeHTTP(proofResponse, hostApplyProofHTTPReq(t, dossier, planned.PlanDigest, f.signature))
	if proofResponse.Code != http.StatusOK {
		t.Fatalf("proof = %d: %s", proofResponse.Code, proofResponse.Body.String())
	}
	var proof hostApplyProofResult
	if err := json.Unmarshal(proofResponse.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	if proof.Schema != hostApplyProofResultSchema || proof.PlanDigest != planned.PlanDigest || !isLowerHex(proof.ProofDigest, 64) || !isLowerHex(proof.AuthorizationID, 64) {
		t.Fatalf("invalid proof result: %+v", proof)
	}

	missingChallenge := httptest.NewRecorder()
	public.ServeHTTP(missingChallenge, httptest.NewRequest(http.MethodGet, hostApplyReceiptPathPrefix+proof.AuthorizationID+".json", nil))
	if missingChallenge.Code != http.StatusNotFound {
		t.Fatalf("receipt without fresh challenge = %d", missingChallenge.Code)
	}
	fresh := httptest.NewRequest(http.MethodGet, hostApplyReceiptPathPrefix+proof.AuthorizationID+".json", nil)
	fresh.Header.Set(hostApplyFreshnessHeader, strings.Repeat("a", 64))
	served := httptest.NewRecorder()
	public.ServeHTTP(served, fresh)
	if served.Code != http.StatusOK || served.Header().Get(hostApplyFreshnessHeader) != strings.Repeat("a", 64) || served.Header().Get("Cache-Control") != "no-store, no-cache" {
		t.Fatalf("fresh receipt = %d headers=%#v body=%s", served.Code, served.Header(), served.Body.String())
	}
	var receipt componentrelease.OneShotApplyAuthorization
	if err := json.Unmarshal(served.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.ComponentID != hostApplyFineractComponentID || receipt.GovernanceReceiptID != dossier || receipt.GovernanceReceiptSHA256 != planned.PlanDigest || receipt.ComponentSHA256 != f.component.SHA256 {
		t.Fatalf("receipt lost immutable host-apply bindings: %+v", receipt)
	}
}

func TestHostApplyCurrentComponentDerivesAndValidatesTenantTarget(t *testing.T) {
	f := newHostApplyPlanFixture(t)
	doc, raw, err := f.svc.loadVerifiedDesiredGeneration()
	if err != nil {
		t.Fatal(err)
	}
	component, target, err := verifyHostApplyCurrentComponent(doc, raw)
	if err != nil {
		t.Fatal(err)
	}
	if component.ComponentID != hostApplyFineractComponentID || target.Base58() != f.targetLicense || target.Base58() == f.storeLicense {
		t.Fatalf("component target did not remain tenant-scoped: component=%+v target=%s store=%s", component, target.Base58(), f.storeLicense)
	}

	doc.Components[0].Chain.LicenseNftMint = "not-a-solana-pubkey"
	if _, _, err := verifyHostApplyCurrentComponent(doc, raw); err == nil {
		t.Fatal("malformed tenant target was accepted")
	}
}

func TestHostApplyProofAndReceiptFailClosedOnMemoOrLiveRevocation(t *testing.T) {
	f := newHostApplyPlanFixture(t)
	const dossier = "fedcba987654321001234567"
	private := newControlReleaseRouter(f.svc)
	public := newPublicRouterWithService(f.svc.cfg, f.svc.operator, f.chain, nil, catalogRuntime{}, f.svc, true)
	planResponse := httptest.NewRecorder()
	private.ServeHTTP(planResponse, hostApplyPlanRequest(t, dossier))
	if planResponse.Code != http.StatusOK {
		t.Fatalf("plan = %d: %s", planResponse.Code, planResponse.Body.String())
	}
	var planned hostApplyPlanResult
	if err := json.Unmarshal(planResponse.Body.Bytes(), &planned); err != nil {
		t.Fatal(err)
	}
	f.armProof(t, planned.Plan)
	bad := f.chain.hostApplyTransactions[f.signature]
	bad.InnerInstructions[0].Instructions[0].Data = primitives.EncodeBase58([]byte("MELUSINA_HOST_APPLY_PLAN_V1:" + strings.Repeat("0", 64)))
	f.chain.hostApplyTransactions[f.signature] = bad
	badProof := httptest.NewRecorder()
	private.ServeHTTP(badProof, hostApplyProofHTTPReq(t, dossier, planned.PlanDigest, f.signature))
	if badProof.Code != http.StatusForbidden {
		t.Fatalf("wrong memo proof = %d: %s", badProof.Code, badProof.Body.String())
	}
	f.armProof(t, planned.Plan)
	proofResponse := httptest.NewRecorder()
	private.ServeHTTP(proofResponse, hostApplyProofHTTPReq(t, dossier, planned.PlanDigest, f.signature))
	if proofResponse.Code != http.StatusOK {
		t.Fatalf("proof = %d: %s", proofResponse.Code, proofResponse.Body.String())
	}
	var proof hostApplyProofResult
	if err := json.Unmarshal(proofResponse.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	f.chain.storeAuthz[f.operatorAuthz] = mockStoreAuthz{status: verify.AuthorizationStatusRevoked}
	revoked := httptest.NewRequest(http.MethodGet, hostApplyReceiptPathPrefix+proof.AuthorizationID+".json", nil)
	revoked.Header.Set(hostApplyFreshnessHeader, strings.Repeat("b", 64))
	response := httptest.NewRecorder()
	public.ServeHTTP(response, revoked)
	if response.Code != http.StatusNotFound {
		t.Fatalf("revoked receipt must disappear = %d: %s", response.Code, response.Body.String())
	}
}

func TestLegacySingleSignerIssueRouteIsGone(t *testing.T) {
	f := newHostApplyPlanFixture(t)
	request := httptest.NewRequest(http.MethodPost, hostApplyIssuePathPrefix+"0123456789abcdef01234567/issue", strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	newControlReleaseRouter(f.svc).ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("legacy single-signer issue route = %d: %s", response.Code, response.Body.String())
	}
}
