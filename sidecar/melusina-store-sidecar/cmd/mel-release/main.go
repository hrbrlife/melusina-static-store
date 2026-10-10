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
//	    Re-validate {candidate, staged bytes, proposal receipt}, read back the
//	    ReleaseEntry the owner-authorized runner registered and admit it (the
//	    frozen app_hash, app_id, release_hash and version, the estate's master
//	    mint and release custodian, a releaseTrust publisher; approve executes
//	    no Squads proposal), re-admit it and promote the catalog pointer
//	    (no-gap), revoke the stale ReleaseEntry LAST when global retirement was
//	    opted into, and emit the terminal receipt.
//
//	mel-release manifest --out <absolute-path>
//	    Re-read every accepted terminal receipt and write the exact immutable
//	    clean-install package manifest. It refuses partial/unserved releases.
//
//	mel-release repair-catalog --app <appId|slug|name>
//	    Re-project ONLY an already terminally accepted candidate through the
//	    store's normal staged-promotion path. It re-verifies terminal, candidate,
//	    stage, and the live Active ReleaseEntry first, then promotes through the
//	    same entry point as approve, which re-admits the ReleaseEntry (owner,
//	    Active, bindings, releaseTrust publisher, signature) immediately before
//	    the promote; it never signs, registers, revokes, or mutates chain state.
//
//	mel-release recover-live --app <appId|slug|name> --spk <absolute-path> --metadata <absolute-path>
//	    Record a missing local release history only after re-hashing selected
//	    source material and proving its exact active ReleaseEntry and served
//	    Bazaar pointer. It is read-only: no stage, approval, promotion, or chain
//	    mutation is possible.
//
//	mel-release abandon-init --app <appId|slug|name>
//	    Archive a stale INIT-only local preflight attempt. It refuses anything
//	    that reached staging, a Squads proposal, or any other mutable boundary.
//
//	mel-release reject-proposed --app <appId|slug|name>
//	    Re-validate and reject one exact, still-unexecuted Squads proposal through
//	    the catalog-pinned shared authority, then archive its complete local WAL.
//	    This is for an invalid candidate that must not be approved; it never
//	    registers, promotes, serves, or revokes a ReleaseEntry.
//
// Config is env-only (MEL_RELEASE_*). mel-release holds no chain key: every
// governed act is delegated to MEL_RELEASE_SIGNER_PROVIDER (see signer.go) and
// the store alone operator-signs the served generation.
//
// It targets no Store of its own. The Store origin, domain and ID, the
// license-registry program, the master mint and the release Squads authority
// all come from the owner-signed estate profile named by
// MEL_RELEASE_ESTATE_PROFILE and pinned by MEL_RELEASE_ESTATE_PROFILE_SHA256
// (see estate.go); the catalog manifest must describe that same Store and
// authority, and the state directory must be this estate's (see
// state_estate.go). Every subcommand refuses before it runs if any of them is
// absent or disagrees.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
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

	var (
		cfg Config
		err error
	)
	if sub == "preflight" {
		// The typed document front door: when the three release documents are
		// given, they are the ONLY estate source — no MEL_RELEASE_* env is
		// required, contradicting overrides are refused by name, and provider
		// selection refuses RELEASE_PROVIDER_UNPINNED while the signed release
		// set carries no release-tools member.
		var documents []string
		documents, rest, err = typedDocumentFlags(rest)
		if err != nil {
			return err
		}
		if documents != nil {
			cfg, _, err = loadTypedPreflightConfig(documents[0], documents[1], documents[2])
			return err
		}
		cfg, err = loadPreflightConfig()
	} else {
		cfg, err = loadConfig()
	}
	if err != nil {
		return err
	}
	catalog, err := LoadCatalog(cfg.ConfigPath)
	if err != nil {
		return err
	}
	if err := cfg.bindCatalog(catalog); err != nil {
		return err
	}
	// Release state is the bound estate's or it is not opened at all (see
	// state_estate.go); every subcommand below reads or writes it.
	if err := cfg.bindStateDir(); err != nil {
		return err
	}
	// The chain is the signed profile's network: every provider-backed
	// subcommand proves its RPC serves that genesis first (estate_chain.go).
	if subcommandReadsChain(sub) {
		if err := requireEstateRPCGenesis(context.Background(), cfg.RPCURL, cfg.estate, rpcGenesisClient); err != nil {
			return fmt.Errorf("MEL_RELEASE_RPC_URL: %w", err)
		}
	}

	switch sub {
	case "preflight":
		fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
		app := fs.String("app", "", "app selector: immutable appId (preferred), publish slug, or name (required)")
		version := fs.String("version", "", "requested release version (required)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		path, err := runPreflight(cfg, catalog, *app, *version)
		if err != nil {
			return err
		}
		fmt.Printf("PREFLIGHT_OK evidence=%s\n", path)
		return nil

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

	case "recover-live":
		fs := flag.NewFlagSet("recover-live", flag.ContinueOnError)
		app := fs.String("app", "", "app selector: immutable appId (preferred), publish slug, or name (required)")
		spk := fs.String("spk", "", "absolute clean path to the selected SPK (required)")
		metadata := fs.String("metadata", "", "absolute clean path to the metadata paired with --spk (required)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *spk == "" || *metadata == "" {
			return fmt.Errorf("recover-live requires --spk and --metadata")
		}
		path, err := runRecoverLive(cfg, catalog, *app, *spk, *metadata)
		if err != nil {
			return err
		}
		fmt.Printf("RECOVER_LIVE_OK receipt=%s\n", path)
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

	case "reject-proposed":
		fs := flag.NewFlagSet("reject-proposed", flag.ContinueOnError)
		app := fs.String("app", "", "app selector: immutable appId (preferred), publish slug, or name (required)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		path, err := runRejectProposed(cfg, catalog, *app)
		if err != nil {
			return err
		}
		fmt.Printf("REJECT_PROPOSED_OK archive=%s\n", path)
		return nil

	case "-h", "--help", "help":
		return usageErr()
	default:
		return fmt.Errorf("unknown subcommand %q (want preflight|publish|approve|manifest|repair-catalog|recover-live|abandon-init|reject-proposed)", sub)
	}
}

// typedDocumentFlags scans preflight flags for the two spellings of the typed
// release-document front door. The long spelling is --estate-profile,
// --release-set and --publisher-device; the second spelling (the C1 estate
// manifest view) is --profile, --manifest and --device. Mixing spellings, or
// supplying one document without all three, refuses. When none is present the
// flags pass through untouched so the legacy environment entry point is
// unchanged.
func typedDocumentFlags(args []string) ([]string, []string, error) {
	long := map[string]string{"--estate-profile": "", "--release-set": "", "--publisher-device": ""}
	short := map[string]string{"--profile": "", "--manifest": "", "--device": ""}
	rest := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		name, value, hasValue := strings.Cut(args[index], "=")
		longest := name == "--estate-profile" || name == "--release-set" || name == "--publisher-device"
		if !longest {
			shortest := name == "--profile" || name == "--manifest" || name == "--device"
			if !shortest {
				rest = append(rest, args[index])
				continue
			}
			if hasValue {
				short[name] = value
			} else if index+1 < len(args) {
				index++
				short[name] = args[index]
			} else {
				return nil, nil, fmt.Errorf("%s requires a value", name)
			}
			continue
		}
		if hasValue {
			long[name] = value
		} else if index+1 < len(args) {
			index++
			long[name] = args[index]
		} else {
			return nil, nil, fmt.Errorf("%s requires a value", name)
		}
	}
	if long["--estate-profile"] == "" && long["--release-set"] == "" && long["--publisher-device"] == "" &&
		short["--profile"] == "" && short["--manifest"] == "" && short["--device"] == "" {
		return nil, args, nil
	}
	documents := []string{long["--estate-profile"], long["--release-set"], long["--publisher-device"]}
	if documents[0] == "" || documents[1] == "" || documents[2] == "" {
		documents = []string{short["--profile"], short["--manifest"], short["--device"]}
		if documents[0] == "" || documents[1] == "" || documents[2] == "" {
			return nil, nil, fmt.Errorf("the typed document front door needs --estate-profile, --release-set and --publisher-device together (or --profile, --manifest and --device)")
		}
	}
	return documents, rest, nil
}

func usageErr() error {
	return fmt.Errorf("usage: mel-release preflight|publish --app <appId|slug|name> --version <v> | approve|repair-catalog|abandon-init|reject-proposed --app <appId|slug|name> | recover-live --app <appId|slug|name> --spk <absolute-path> --metadata <absolute-path> | manifest --out <absolute-path>")
}
