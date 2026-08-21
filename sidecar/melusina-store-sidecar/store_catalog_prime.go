package main

import (
	"context"
	"strings"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// primedChainReader answers the two PER-ROW reads from a snapshot fetched in one
// batch, and falls through to the live reader for anything it was not primed
// with. The authz and blacklist reads are request-INVARIANT and are collapsed by
// memoChainReader instead; these two genuinely differ per app, so a batch is the
// only thing that removes them.
//
// It decodes with the SAME functions the live single-read path uses
// (readReleaseEntryMeta, readStoreReleaseListingMeta) and reproduces its exact
// handling of an absent account (verify.ErrPDANotFound) and of the PDA field.
// Reusing the decoders rather than reimplementing them is what makes drift
// impossible: there is no second copy to fall out of step.
type primedChainReader struct {
	chainReader
	snap map[string]accountValue
}

func (p *primedChainReader) FetchReleaseEntryMeta(ctx context.Context, addr string) (releaseEntryMeta, error) {
	value, ok := p.snap[addr]
	if !ok {
		return p.chainReader.FetchReleaseEntryMeta(ctx, addr)
	}
	if !value.present {
		return releaseEntryMeta{}, verify.ErrPDANotFound
	}
	meta, err := readReleaseEntryMeta(value.data)
	if err != nil {
		return releaseEntryMeta{}, err
	}
	meta.PDA = addr
	return meta, nil
}

func (p *primedChainReader) FetchStoreReleaseListingMeta(ctx context.Context, addr string) (storeReleaseListingMeta, error) {
	value, ok := p.snap[addr]
	if !ok {
		return p.chainReader.FetchStoreReleaseListingMeta(ctx, addr)
	}
	if !value.present {
		return storeReleaseListingMeta{}, verify.ErrPDANotFound
	}
	meta, err := readStoreReleaseListingMeta(value.data)
	if err != nil {
		return storeReleaseListingMeta{}, err
	}
	meta.PDA = addr
	return meta, nil
}

// primeCatalogAccounts fetches every per-row account this request will need in
// one batched call and returns a reader that answers from it.
//
// It is strictly an accelerator and degrades to the unmodified reader on ANY
// difficulty: a reader without batch support, a derivation that fails, or a
// batch that errors. It NEVER synthesises an answer and never marks an account
// absent that it did not observe absent — a miss simply falls through to a live
// read, which is the behaviour that existed before.
// batchSource is passed SEPARATELY from inner and that separation is
// load-bearing. inner is normally a memoChainReader, which embeds a chainReader
// INTERFACE — an interface that does not declare fetchMultipleAccounts — so a
// type assertion on inner can never succeed no matter what concrete reader sits
// underneath. Asserting on inner would compile, pass every test that does not
// count reads, deploy through the governed rail, and quietly prime nothing.
func primeCatalogAccounts(ctx context.Context, cfg Config, inner chainReader, batchSource any, candidates []catalogGateCandidate) chainReader {
	batch, ok := batchSource.(multiAccountReader)
	if !ok {
		return inner
	}
	storeAuthority, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.StoreAuthority))
	if err != nil {
		return inner
	}
	addrs := make([]string, 0, 2*len(candidates))
	seen := make(map[string]struct{}, 2*len(candidates))
	add := func(a string) {
		if _, dup := seen[a]; dup {
			return
		}
		seen[a] = struct{}{}
		addrs = append(addrs, a)
	}
	for _, candidate := range candidates {
		rel := candidate.app.rel
		appHash, err := hash32FromHex(strings.ToLower(strings.TrimSpace(rel.AppHash)))
		if err != nil {
			continue // this row falls through to a live read
		}
		masterMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(rel.MasterNftMint))
		if err != nil {
			continue
		}
		if relPDA, _, err := pda.Release(masterMint, appHash, programID); err == nil {
			add(relPDA.Base58())
		}
		if listingPDA, _, err := pda.StoreReleaseListing(storeAuthority, appHash, programID); err == nil {
			add(listingPDA.Base58())
		}
	}
	if len(addrs) == 0 {
		return inner
	}
	values, err := batch.fetchMultipleAccounts(ctx, addrs)
	if err != nil || len(values) != len(addrs) {
		// A failed prime must not fail the request: the live path still works.
		// The length guard is belt and braces over fetchMultipleAccounts' own.
		return inner
	}
	snap := make(map[string]accountValue, len(addrs))
	for i, addr := range addrs {
		snap[addr] = values[i]
	}
	return &primedChainReader{chainReader: inner, snap: snap}
}
