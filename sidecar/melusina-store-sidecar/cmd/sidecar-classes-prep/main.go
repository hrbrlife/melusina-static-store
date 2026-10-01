// Command sidecar-classes-prep is the PRODUCER of the Store's signed sidecar
// class table (K-CHN-33): the one real, documented process that signs the
// estate's per-sidecar class declaration with the boot-identity operator key
// (the same authority that signs the desired generation), writing the table
// document, the detached base58 signature and the operator's public key as
// the exact three files the Store's own config (sidecar_classes.path /
// signature_path / authorized_operator_key) and the deployer's host startup
// loader consume.
//
// The row set is NEVER hand-listed here: the operator passes a declaration
// file (rows JSON); the command only derives, signs and writes. Who may
// declare which class is the operator's provision-time authority recorded
// per row in Source; this tool refuses to invent a row, default a class, or
// sign an empty table.
//
// Usage:
//
//	sidecar-classes-prep -config store.config.json \
//	  -declaration classes.json -out-dir /var/lib/melusina-store/sidecar-classes/
//
// The operator key is derived exactly as Store startup derives it: from the
// three attest shards under the config's boot_identity ref (so the key that
// signs the table is the key the Store's pinned config expects), or supplied
// explicitly with -shards-dir when operating outside a full Store config.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/sidecarclasses"
)

// declaration is the operator's per-sidecar class declaration input. Rows are
// echoed verbatim into the signed table; the tool refuses to default a class.
type declaration struct {
	Rows []sidecarclasses.Row `json:"rows"`
}

type options struct {
	configPath     string
	declaration    string
	outDir         string
	shardsDir      string
	chainID        string
	programID      string
	licenseMint    string
	domain         string
	sidecarID      string
	operatorDomain string
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "sidecar-classes-prep: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	// Load the declaration BEFORE deriving the operator: an unusable
	// declaration must not touch the shard material.
	declRaw, err := readBoundedInput(opts.declaration, "declaration")
	if err != nil {
		return err
	}
	var decl declaration
	if err := json.Unmarshal(declRaw, &decl); err != nil {
		return fmt.Errorf("declaration: %w", err)
	}
	if len(decl.Rows) == 0 {
		return fmt.Errorf("declaration has no rows: refusing to sign an empty sidecar class table (the class of every sidecar is a signed estate fact, never an absent one)")
	}
	seen := map[string]bool{}
	for _, row := range decl.Rows {
		if strings.TrimSpace(row.ID) == "" {
			return fmt.Errorf("declaration row with an empty id")
		}
		if seen[row.ID] {
			return fmt.Errorf("declaration names sidecar %q twice", row.ID)
		}
		seen[row.ID] = true
		switch row.Class {
		case sidecarclasses.ClassCascade, sidecarclasses.ClassIdentity:
		default:
			return fmt.Errorf("sidecar %s: unknown class %q (want %s or %s)", row.ID, row.Class, sidecarclasses.ClassCascade, sidecarclasses.ClassIdentity)
		}
		if row.Source == "" {
			return fmt.Errorf("sidecar %s: row lacks Source provenance (G-2: every declared class records its derivation)", row.ID)
		}
	}

	// Derive the operator exactly as the Store does: three shards under the
	// boot identity ref (see boot_identity.go / boot-identity-prep). A config
	// supplies every ref field; the standalone flags exist only for rehearsal.
	ref, shardsDir, err := resolveOperatorInputs(opts)
	if err != nil {
		return err
	}
	shards, err := loadShardsForPrep(shardsDir)
	if err != nil {
		return err
	}
	operator, err := deriveSidecarOperatorForPrep(ref, shards)
	if err != nil {
		return err
	}
	storeID := strings.TrimSpace(opts.storeID())
	if storeID == "" {
		return fmt.Errorf("store_id is required: the signed table's destination is this Store's own id (K-CHN-33), never omitted")
	}
	signedAt := prepClockNow()
	doc, err := sidecarclasses.Sign(operator, sidecarclasses.Table{
		StoreID:      storeID,
		SignedAtUnix: signedAt,
		Rows:         decl.Rows,
	})
	if err != nil {
		return fmt.Errorf("sign sidecar class table: %w", err)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(opts.outDir, 0o700); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}
	docPath := filepath.Join(opts.outDir, "sidecar-classes.json")
	sigPath := filepath.Join(opts.outDir, "sidecar-classes.signature")
	keyPath := filepath.Join(opts.outDir, "sidecar-classes.operator.pub")
	if err := os.WriteFile(docPath, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(sigPath, []byte(doc.OperatorSignature+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, []byte(doc.OperatorPubkey+"\n"), 0o644); err != nil {
		return err
	}
	report := map[string]string{
		"document":          docPath,
		"signature":         sigPath,
		"operatorPublicKey": keyPath,
		"storeId":           storeID,
		"rows":              fmt.Sprintf("%d", len(decl.Rows)),
		"configHint":        `wire these into the Store config: {"sidecar_classes":{"path":"` + docPath + `","signature_path":"` + sigPath + `","authorized_operator_key":"` + doc.OperatorPubkey + `"}}`,
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func parseOptions(args []string) (options, error) {
	var opts options
	fs := flag.NewFlagSet("sidecar-classes-prep", flag.ContinueOnError)
	fs.StringVar(&opts.configPath, "config", "", "Store config JSON; supplies store_id and the boot-identity ref (shards dir, chain, program, license mint, domain, sidecar id)")
	fs.StringVar(&opts.declaration, "declaration", "", "operator's class declaration JSON ({\"rows\":[{...}]}); rows are signed verbatim, never defaulted")
	fs.StringVar(&opts.outDir, "out-dir", "", "directory for the three output files (document, detached signature, operator public key)")
	fs.StringVar(&opts.shardsDir, "shards-dir", "", "override the shards directory (else the config's boot_identity.shards_dir)")
	fs.StringVar(&opts.chainID, "chain-id", "", "override the attest chain id (else the config's boot_identity.chain_id)")
	fs.StringVar(&opts.programID, "program-id", "", "override the license-registry program id (else the config's program_id)")
	fs.StringVar(&opts.licenseMint, "license-mint", "", "override the license NFT mint (else the config's license_nft_mint)")
	fs.StringVar(&opts.domain, "domain", "", "override the store domain (else the config's domain)")
	fs.StringVar(&opts.sidecarID, "sidecar-id", "", "override the boot identity sidecar id (else the config's boot_identity.sidecar_id)")
	fs.StringVar(&opts.operatorDomain, "operator-domain", "", "override the operator identity domain (else the config's boot_identity.operator_domain or the domain)")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional args: %v", fs.Args())
	}
	if strings.TrimSpace(opts.declaration) == "" {
		return options{}, fmt.Errorf("-declaration is required: the class of every sidecar is the operator's declaration, never derived or defaulted here")
	}
	if strings.TrimSpace(opts.outDir) == "" {
		return options{}, fmt.Errorf("-out-dir is required")
	}
	return opts, nil
}

// storeID resolves from the config when given.
func (o options) storeID() string {
	if o.configPath == "" {
		return ""
	}
	raw, err := os.ReadFile(o.configPath)
	if err != nil {
		return ""
	}
	var doc struct {
		StoreID string `json:"store_id"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ""
	}
	return doc.StoreID
}
