package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/finalizationinput"
	"github.com/hrbrlife/melusina-store-sidecar/staging"
)

const (
	listen          = "127.0.0.1:18510"
	origin          = "http://" + listen
	storeURL        = "https://bazaar.melusina-os.org"
	appID           = "zukk3pav049f7wr4a12x76ytpgmsyt3136sz1hev4zy8g33f1310"
	version         = "0.1.0"
	source          = "161b99160c5f47dcdacb8b68b57bced0d6b88c95"
	spkSHA          = "1228db1458c0f3e2955031b257a2347708687f310fd421e9da40cdcea73a2f34"
	spkBytes        = 14027720
	metaSHA         = "fd10a4d5fc5d465db59a3a3f6d34a886081a5b98a65d00e4344807e7bcc9c59c"
	runtimeSHA      = "e9badc3858ff3a971f3399e14d90a86a0da43089dd110989667cb91e2b465e46"
	appHash         = "a3172ddafb512da90139f225ba225e70536360fc0e07934930b36b18b6c335c3"
	releaseHash     = "a4b0474c1e70851373bafe831324845cfde864630c127a30bb476529f767a6c7"
	master          = "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe"
	registry        = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	core            = "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"
	vault           = "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3"
	publisher       = "ARX39MQQR1c7cT8L9ARbeg7AWw975gPGr9EE9oygKv1P"
	operator        = "4J2hbufiTKmvgfxjGVNqhoQXiKVDsYwaor6hcaDKjzZV"
	license         = "9yfmmcTG8BBiSPHf6kZC77tUzm46VMnfyrLzd3E2ii9J"
	domain          = "bazaar.melusina-os.org"
	rpcURL          = "https://api.devnet.solana.com"
	runtimeArtifact = "8fff30321ed863475947e2dac28e05df93bd4bf12fef79423a08f3e0797b77bb"
)

var members = [4]string{publisher, "8stvUEVXhaPiXecztiXc4cAmE2pVrMjBVZSQMNmHU4rC", "7hG6N24krBwu2hgNkfin7XVSAUmtcAv7CCUqtzUfMKvV", "133bmq4L4iPfcCeGzjYHLtUXFYMQniHb6ZNVBoEnXpWC"}

type candidate struct {
	dir                                         string
	spk, metadata, runtime, provisional, author []byte
	ceremony                                    finalizationinput.CeremonyState
	stageID, digest                             string
	destination                                 identity.Public
}
type publicPlan struct {
	Schema   string           `json:"schema"`
	Ceremony json.RawMessage  `json:"ceremony"`
	Stage    *staging.Receipt `json:"stageReceipt"`
}
type prepared struct {
	Schema   string          `json:"schema"`
	Target   string          `json:"target"`
	Envelope envelope.Signed `json:"envelope"`
	Expected struct {
		AppID       string `json:"appId"`
		AppHash     string `json:"appHash"`
		ReleaseHash string `json:"releaseHash"`
		StageID     string `json:"stageId"`
	} `json:"expected"`
}

func sha(b []byte) string      { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func hash32(s string) [32]byte { var h [32]byte; b, _ := hex.DecodeString(s); copy(h[:], b); return h }
func stageID() string {
	r := hash32(runtimeSHA)
	return staging.StageID(staging.Identity{SPKSHA256: hash32(spkSHA), MetadataSHA256: hash32(metaSHA), ReleaseHash: hash32(releaseHash), RuntimeContractSHA256: &r, Version: version, MasterNftMint: master, Developer: "melusina-os", Repo: "bazaar-control-pearl", Slug: "bazaar-control"})
}
func owned(name string, max int64) ([]byte, error) {
	f, e := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil {
		return nil, e
	}
	v, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.Mode().IsRegular() || s.Size() <= 0 || s.Size() > max || v.Uid != uint32(os.Getuid()) || v.Nlink != 1 || s.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("owned protected bounded input required")
	}
	return io.ReadAll(io.LimitReader(f, max+1))
}
func privateDir(name string) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return errors.New("canonical absolute directory required")
	}
	resolved, e := filepath.EvalSymlinks(name)
	if e != nil || resolved != name {
		return errors.New("directory symlink refused")
	}
	s, e := os.Stat(name)
	if e != nil {
		return e
	}
	v, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.IsDir() || v.Uid != uint32(os.Getuid()) || s.Mode().Perm() != 0o700 {
		return errors.New("original private owned directory required")
	}
	return nil
}
func exact(raw []byte, out any) error {
	var tree any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e := d.Decode(&tree); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	if e := unique(raw); e != nil {
		return e
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	b, e := json.Marshal(out)
	if e != nil {
		return e
	}
	var want any
	d = json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&want); e != nil {
		return e
	}
	if !reflect.DeepEqual(tree, want) {
		return errors.New("aliased or ambiguous JSON")
	}
	return nil
}
func unique(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON depth exceeded")
		}
		v, e := d.Token()
		if e != nil {
			return e
		}
		switch v {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				v, e := d.Token()
				if e != nil {
					return e
				}
				k, ok := v.(string)
				if !ok || seen[k] {
					return errors.New("duplicate JSON key")
				}
				seen[k] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		case json.Delim('['):
			for d.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	return walk(0)
}
func loadCandidate(dir string) (candidate, error) {
	c := candidate{dir: dir, stageID: stageID()}
	if e := privateDir(dir); e != nil {
		return c, e
	}
	var e error
	for _, v := range []struct {
		name, want string
		max        int64
		dst        *[]byte
	}{{"app/app.spk", spkSHA, spkBytes, &c.spk}, {"app/metadata.json", metaSHA, 1 << 20, &c.metadata}, {"RUNTIME-CONTRACT.json", runtimeSHA, 1 << 20, &c.runtime}} {
		*v.dst, e = owned(filepath.Join(dir, v.name), v.max)
		if e != nil {
			return c, e
		}
		if sha(*v.dst) != v.want {
			return c, errors.New("exact original first Bazaar artifact changed")
		}
	}
	if len(c.spk) != spkBytes {
		return c, errors.New("exact SPK size differs")
	}
	h, e := apphash.Canonical(bytes.NewReader(c.spk), c.metadata)
	if e != nil || h != appHash {
		return c, errors.New("original AppHash differs")
	}
	c.author, e = owned(filepath.Join(dir, "author-ceremony.json"), 128<<10)
	if e != nil {
		return c, e
	}
	c.ceremony, e = finalizationinput.DecodePreparedCeremony(c.author)
	if e != nil {
		return c, e
	}
	s := c.ceremony
	if s.AppID != appID || s.Version != version || s.AppHash != appHash || s.ReleaseHash != releaseHash || s.MasterNftMint != master || s.ProgramID != registry || s.MultisigPDA != core || s.LicenseSquadsVault != vault || s.PublisherEd25519Pubkey != publisher || s.QuorumPolicy.Threshold != 3 || s.QuorumPolicy.MemberCount != 4 {
		return c, errors.New("author escaped original first Bazaar and Core scope")
	}
	c.provisional, e = owned(filepath.Join(dir, "RELEASE.provisional.json"), 128<<10)
	if e != nil {
		return c, e
	}
	if e = validateRelease(c, c.provisional, s.CreatedAtUnix); e != nil {
		return c, e
	}
	pub, e := assets.ReadFile("original-store-public.json")
	if e != nil || sha(pub) != "0750ade356004583023a3eff76395a326d94e4b4a5f853f039d082d7f8a1b79e" {
		return c, errors.New("original Store identity changed")
	}
	if e = json.Unmarshal(pub, &c.destination); e != nil {
		return c, e
	}
	if c.destination.SignPubkeyB58 != operator {
		return c, errors.New("original Store operator differs")
	}
	c.digest = sha([]byte("melusina-first-bazaar-publication-v1\x00" + sha(c.author) + spkSHA + metaSHA + runtimeSHA + c.stageID))
	return c, nil
}
func validateRelease(c candidate, b []byte, at int64) error {
	r, e := finalizationinput.DecodeReleaseDescriptor(b)
	if e != nil {
		return e
	}
	s := c.ceremony
	want := finalizationinput.ReleaseClaims{Schema: "melusina-release-v1", AppHash: appHash, ReleaseHash: releaseHash, Version: version, SignedAtUnix: at, MasterNftMint: master, LicenseSquadsVault: vault, ReleaseEntryPDA: s.ReleaseEntryPDA, AuthorSig: s.AuthorSig, QuorumPolicy: s.QuorumPolicy, ReleaseNonce: s.ReleaseNonce, RuntimeContractSHA256: runtimeSHA, RuntimeContractSchema: "melusina-app-runtime-contract-v1"}
	if r != want {
		return errors.New("release differs from exact prepared author or observed registration time")
	}
	return nil
}
func submission(c candidate, target string, release, raw []byte) ([]byte, error) {
	var p prepared
	if e := exact(raw, &p); e != nil {
		return nil, e
	}
	if p.Schema != "melusina-submit-prepared-v1" || p.Target != target || p.Expected.AppID != appID || p.Expected.AppHash != appHash || p.Expected.ReleaseHash != releaseHash || p.Expected.StageID != c.stageID {
		return nil, errors.New("prepared handoff differs from exact first candidate")
	}
	e := p.Envelope.Payload
	if e.Method != "POST" || e.Target != target || e.BodyHashHex != sha(release) || e.ChainEvidence.ChainID != "solana:devnet" || e.ChainEvidence.ProgramID != registry || e.ChainEvidence.VerifiedSlot == 0 || e.ChainEvidence.ReleaseEntryPDA != c.ceremony.ReleaseEntryPDA {
		return nil, errors.New("publisher envelope scope differs")
	}
	if err := envelope.Verify(p.Envelope, envelope.VerifyOptions{ExpectedKind: envelope.KindPublishRequest, ExpectedSignerPubkeyB58: publisher, ExpectedDestination: &c.destination, ExpectedRequestHash: spkSHA, NonceCache: envelope.NewMemoryNonceCache()}); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Envelope  envelope.Signed `json:"envelope"`
		Release   string          `json:"release_b64"`
		SPK       string          `json:"spk_b64"`
		Metadata  string          `json:"metadata_b64"`
		Runtime   string          `json:"runtime_contract_b64"`
		Developer string          `json:"developer"`
		Repo      string          `json:"repo"`
		Slug      string          `json:"slug"`
	}{p.Envelope, base64.StdEncoding.EncodeToString(release), base64.StdEncoding.EncodeToString(c.spk), base64.StdEncoding.EncodeToString(c.metadata), base64.StdEncoding.EncodeToString(c.runtime), "melusina-os", "bazaar-control-pearl", "bazaar-control"})
}
