// Command mel-release is the ONE consolidated app-release CLI for every app
// declared in fleet/bazaar-catalog.yaml, keyed on the IMMUTABLE
// appId. It replaces the three separate clients —
// cmd/submit (store stage/publish), cmd/publish-supersede (no-gap register/
// promote/revoke WAL), and cmd/submit-generation (signed DesiredGeneration) —
// with two release subcommands split at a real authority boundary, plus a
// receipt-only manifest command for clean deployment:
//
//	mel-release publish --app <appId|slug|name> --version <v>
//	    Build + local app_hash pre-check + private store stage + UNEXECUTED Squads
//	    register proposal + an IMMUTABLE candidate receipt. Nothing is Active,
//	    nothing is served, nothing is catalog-visible.
//
//	mel-release approve --app <appId|slug|name>
//	    Re-validate {candidate, staged bytes, pending proposal}, execute the
//	    authorized Squads approval (ReleaseEntry Active), promote the catalog
//	    pointer (no-gap), submit + read-back-verify the single-component signed
//	    DesiredGeneration in the frozen componentrelease release_v2 format, then
//	    revoke the stale ReleaseEntry LAST, and emit the terminal receipt.
//
//	mel-release manifest --out <absolute-path>
//	    Re-read every accepted terminal receipt and write the exact immutable
//	    clean-install package manifest. It refuses partial/unserved releases.
//
//	mel-release repair-catalog --app <appId|slug|name>
//	    Re-project ONLY an already terminally accepted candidate through the
//	    store's normal staged-promotion path. It re-verifies terminal, candidate,
//	    stage, and the live Active ReleaseEntry first; it never signs, registers,
//	    revokes, or mutates chain state.
//
//	mel-release abandon-init --app <appId|slug|name>
//	    Archive a stale INIT-only local preflight attempt. It refuses anything
//	    that reached staging, a Squads proposal, or any other mutable boundary.
//
// Config is env-only (MEL_RELEASE_*). mel-release holds no chain key: every
// governed act is delegated to MEL_RELEASE_SIGNER_PROVIDER (see signer.go) and
// the store alone operator-signs the served generation.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mel-release:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageErr()
	}
	sub := args[0]
	rest := args[1:]

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	catalog, err := LoadCatalog(cfg.ConfigPath)
	if err != nil {
		return err
	}
	if err := cfg.bindCatalogSquadsAuthority(catalog); err != nil {
		return err
	}

	switch sub {
	case "publish":
		fs := flag.NewFlagSet("publish", flag.ContinueOnError)
		app := fs.String("app", "", "app selector: immutable appId (preferred), publish slug, or name (required)")
		version := fs.String("version", "", "new release version, strictly greater than the current Active (required)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		path, err := runPublish(cfg, catalog, *app, *version)
		if err != nil {
			return err
		}
		fmt.Printf("PUBLISH_OK candidate=%s\n", path)
		return nil

	case "approve":
		fs := flag.NewFlagSet("approve", flag.ContinueOnError)
		app := fs.String("app", "", "app selector: immutable appId (preferred), publish slug, or name (required)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		path, err := runApprove(cfg, catalog, *app)
		if err != nil {
			return err
		}
		fmt.Printf("APPROVE_OK terminal=%s\n", path)
		return nil

	case "manifest":
		fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
		out := fs.String("out", "", "absolute output path for the governed clean-install manifest (required)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *out == "" {
			return fmt.Errorf("manifest requires --out")
		}
		if err := runManifest(cfg, catalog, *out); err != nil {
			return err
		}
		fmt.Printf("MANIFEST_OK path=%s\n", *out)
		return nil

	case "repair-catalog":
		fs := flag.NewFlagSet("repair-catalog", flag.ContinueOnError)
		app := fs.String("app", "", "app selector: immutable appId (preferred), publish slug, or name (required)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		path, err := runRepairCatalog(cfg, catalog, *app)
		if err != nil {
			return err
		}
		fmt.Printf("REPAIR_CATALOG_OK receipt=%s\n", path)
		return nil

	case "abandon-init":
		fs := flag.NewFlagSet("abandon-init", flag.ContinueOnError)
		app := fs.String("app", "", "app selector: immutable appId (preferred), publish slug, or name (required)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		path, err := runAbandonInit(cfg, catalog, *app)
		if err != nil {
			return err
		}
		fmt.Printf("ABANDON_INIT_OK archive=%s\n", path)
		return nil

	case "-h", "--help", "help":
		return usageErr()
	default:
		return fmt.Errorf("unknown subcommand %q (want publish|approve|manifest|repair-catalog|abandon-init)", sub)
	}
}

func usageErr() error {
	return fmt.Errorf("usage: mel-release publish --app <appId|slug|name> --version <v> | approve|repair-catalog|abandon-init --app <appId|slug|name> | manifest --out <absolute-path>")
}
