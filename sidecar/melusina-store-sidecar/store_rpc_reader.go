package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const releaseEntryAppIDOffset = verify.AccountDiscriminatorLen + 32 + 32

const (
	defaultRPCAttempts = 2
	maxRPCAttempts     = 3
	rpcRetryDelay      = 100 * time.Millisecond
)

type storeRPCReader struct {
	*verify.RPCClient
}

func newStoreRPCReader(endpoint string) *storeRPCReader {
	return &storeRPCReader{RPCClient: verify.NewRPCClient(endpoint)}
}

// rpcFailoverChainReader keeps the existing verification semantics while
// making the transport underneath them resilient.  It retries only failures
// explicitly marked ErrRPCUnreachable.  A valid RPC answer that says an
// account is absent, revoked, malformed, or otherwise invalid is returned
// immediately and remains fail-closed.
type rpcFailoverChainReader struct {
	readers    []chainReader
	rawReaders []rawAccountReader
	// multiReaders parallels readers for batched reads. chainReader has no batch
	// method, so this cannot ride on readers; keeping the slices index-aligned is
	// what makes the batch path fail over across the SAME endpoints in the SAME
	// order as every other read.
	multiReaders []multiAccountReader
	attempts     int
	delay        time.Duration
}

var _ chainReader = (*rpcFailoverChainReader)(nil)
var _ rawAccountReader = (*rpcFailoverChainReader)(nil)

func newConfiguredStoreRPCReader(cfg Config) chainReader {
	readers := make([]chainReader, 0, 1+len(cfg.RPCFallbackURLs))
	rawReaders := make([]rawAccountReader, 0, 1+len(cfg.RPCFallbackURLs))
	multiReaders := make([]multiAccountReader, 0, 1+len(cfg.RPCFallbackURLs))
	primary := newStoreRPCReader(cfg.RPCURL)
	readers = append(readers, primary)
	rawReaders = append(rawReaders, primary)
	multiReaders = append(multiReaders, primary)
	for _, endpoint := range cfg.RPCFallbackURLs {
		reader := newStoreRPCReader(endpoint)
		readers = append(readers, reader)
		rawReaders = append(rawReaders, reader)
		multiReaders = append(multiReaders, reader)
	}
	attempts := cfg.RPCAttempts
	if attempts == 0 {
		attempts = defaultRPCAttempts
	}
	return &rpcFailoverChainReader{readers: readers, rawReaders: rawReaders, multiReaders: multiReaders, attempts: attempts, delay: rpcRetryDelay}
}

func (c *rpcFailoverChainReader) call(ctx context.Context, invoke func(context.Context, chainReader) error) error {
	var transientFailures int
	for readerIndex, reader := range c.readers {
		for attempt := 0; attempt < c.attempts; attempt++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			err := invoke(ctx, reader)
			if err == nil {
				return nil
			}
			if !errors.Is(err, verify.ErrRPCUnreachable) {
				return err
			}
			transientFailures++
			if attempt+1 < c.attempts || readerIndex+1 < len(c.readers) {
				if err := waitForRPCRetry(ctx, c.delay); err != nil {
					return err
				}
			}
		}
	}
	return fmt.Errorf("%w: all configured RPC attempts failed (%d transport failure(s))", verify.ErrRPCUnreachable, transientFailures)
}

func waitForRPCRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *rpcFailoverChainReader) FetchReleaseEntry(ctx context.Context, addr string) (appHash [32]byte, status verify.AttestationStatus, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		appHash, status, err = reader.FetchReleaseEntry(ctx, addr)
		return err
	})
	return appHash, status, err
}

func (c *rpcFailoverChainReader) FetchReleaseEntryMeta(ctx context.Context, addr string) (meta releaseEntryMeta, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		meta, err = reader.FetchReleaseEntryMeta(ctx, addr)
		return err
	})
	return meta, err
}

func (c *rpcFailoverChainReader) FetchStoreReleaseListingMeta(ctx context.Context, addr string) (meta storeReleaseListingMeta, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		meta, err = reader.FetchStoreReleaseListingMeta(ctx, addr)
		return err
	})
	return meta, err
}

func (c *rpcFailoverChainReader) FetchActiveReleaseEntriesByAppID(ctx context.Context, appID [32]byte) (entries []releaseEntryMeta, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		entries, err = reader.FetchActiveReleaseEntriesByAppID(ctx, appID)
		return err
	})
	return entries, err
}

func (c *rpcFailoverChainReader) FetchReleaseEntryAppID(ctx context.Context, addr string) (appID [32]byte, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		appID, err = reader.FetchReleaseEntryAppID(ctx, addr)
		return err
	})
	return appID, err
}

func (c *rpcFailoverChainReader) FetchStoreOperatorAuthz(ctx context.Context, addr string) (status verify.AuthorizationStatus, authority verify.Pubkey, tierMask uint8, isRoot bool, domainHash [32]byte, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		status, authority, tierMask, isRoot, domainHash, err = reader.FetchStoreOperatorAuthz(ctx, addr)
		return err
	})
	return status, authority, tierMask, isRoot, domainHash, err
}

func (c *rpcFailoverChainReader) FetchLicenseEntry(ctx context.Context, addr string) (entry licenseEntryHead, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		entry, err = reader.FetchLicenseEntry(ctx, addr)
		return err
	})
	return entry, err
}

func (c *rpcFailoverChainReader) FetchResellerEntry(ctx context.Context, addr string) (entry verify.ResellerEntry, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		entry, err = reader.FetchResellerEntry(ctx, addr)
		return err
	})
	return entry, err
}

func (c *rpcFailoverChainReader) FetchBlacklistStatusAccount(ctx context.Context, addr string) (account *verify.Account, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		account, err = reader.FetchBlacklistStatusAccount(ctx, addr)
		return err
	})
	return account, err
}

func (c *rpcFailoverChainReader) FetchInstallerReleaseEntryMeta(ctx context.Context, addr string) (meta installerReleaseMeta, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		meta, err = reader.FetchInstallerReleaseEntryMeta(ctx, addr)
		return err
	})
	return meta, err
}

func (c *rpcFailoverChainReader) FetchFoundationAppEntry(ctx context.Context, addr string) (appID [32]byte, tier uint8, status verify.ApprovalStatus, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		appID, tier, status, err = reader.FetchFoundationAppEntry(ctx, addr)
		return err
	})
	return appID, tier, status, err
}

func (c *rpcFailoverChainReader) FetchSidecarIdentity(ctx context.Context, addr string) (identity verify.SidecarIdentity, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		identity, err = reader.FetchSidecarIdentity(ctx, addr)
		return err
	})
	return identity, err
}

// fetchRawAccount preserves the raw cascade-reader capability through the
// retry/failover wrapper. The sidecar component gate needs account owners as
// well as bytes, so falling back to the higher-level chainReader methods would
// weaken the on-chain authorization cascade.
func (c *rpcFailoverChainReader) fetchRawAccount(ctx context.Context, addr string) (data []byte, owner string, err error) {
	if len(c.rawReaders) != len(c.readers) || len(c.rawReaders) == 0 {
		return nil, "", errors.New("chain reader does not support the raw cascade reads required by require_active_sidecar_cascade")
	}
	var transientFailures int
	for readerIndex, reader := range c.rawReaders {
		for attempt := 0; attempt < c.attempts; attempt++ {
			if err := ctx.Err(); err != nil {
				return nil, "", err
			}
			data, owner, err = reader.fetchRawAccount(ctx, addr)
			if err == nil {
				return data, owner, nil
			}
			if !errors.Is(err, verify.ErrRPCUnreachable) {
				return nil, "", err
			}
			transientFailures++
			if attempt+1 < c.attempts || readerIndex+1 < len(c.rawReaders) {
				if err := waitForRPCRetry(ctx, c.delay); err != nil {
					return nil, "", err
				}
			}
		}
	}
	return nil, "", fmt.Errorf("%w: all configured RPC attempts failed (%d transport failure(s))", verify.ErrRPCUnreachable, transientFailures)
}

func (c *storeRPCReader) FetchReleaseEntryMeta(ctx context.Context, addr string) (releaseEntryMeta, error) {
	data, err := c.GetAccountInfo(ctx, addr)
	if err != nil {
		return releaseEntryMeta{}, err
	}
	if data == nil {
		return releaseEntryMeta{}, verify.ErrPDANotFound
	}
	meta, err := readReleaseEntryMeta(data)
	if err != nil {
		return releaseEntryMeta{}, err
	}
	meta.PDA = addr
	return meta, nil
}

func (c *storeRPCReader) FetchStoreReleaseListingMeta(ctx context.Context, addr string) (storeReleaseListingMeta, error) {
	data, err := c.GetAccountInfo(ctx, addr)
	if err != nil {
		return storeReleaseListingMeta{}, err
	}
	if data == nil {
		return storeReleaseListingMeta{}, verify.ErrPDANotFound
	}
	meta, err := readStoreReleaseListingMeta(data)
	if err != nil {
		return storeReleaseListingMeta{}, err
	}
	meta.PDA = addr
	return meta, nil
}

func (c *storeRPCReader) FetchInstallerReleaseEntryMeta(ctx context.Context, addr string) (installerReleaseMeta, error) {
	data, err := c.GetAccountInfo(ctx, addr)
	if err != nil {
		return installerReleaseMeta{}, err
	}
	if data == nil {
		return installerReleaseMeta{}, verify.ErrPDANotFound
	}
	meta, err := readInstallerReleaseEntryMeta(data)
	if err != nil {
		return installerReleaseMeta{}, err
	}
	meta.PDA = addr
	return meta, nil
}

func (c *storeRPCReader) FetchActiveReleaseEntriesByAppID(ctx context.Context, appID [32]byte) ([]releaseEntryMeta, error) {
	accounts, err := c.getProgramAccountsByAppID(ctx, appID)
	if err != nil {
		return nil, err
	}
	out := make([]releaseEntryMeta, 0, len(accounts))
	for _, acct := range accounts {
		meta, err := readReleaseEntryMeta(acct.Data)
		if err != nil {
			return nil, fmt.Errorf("decode release entry %s: %w", acct.Pubkey, err)
		}
		if meta.AppID != appID {
			continue
		}
		if meta.Status == verify.AttestationStatusActive {
			meta.PDA = acct.Pubkey
			out = append(out, meta)
		}
	}
	return out, nil
}

type programAccount struct {
	Pubkey string
	Data   []byte
}

// releaseEntryByAppIDFilters selects exactly the ReleaseEntry accounts for
// appID: the account size is ReleaseEntry::LEN, the Anchor discriminator is
// ReleaseEntry's, and app_id matches. readReleaseEntryMeta decodes only that
// layout, so the query asks for nothing else: another account type the
// program owns that happens to hold these 32 bytes at the app_id offset is
// not a release and is not returned to be refused.
func releaseEntryByAppIDFilters(appID [32]byte) []any {
	discriminator := releaseentry.Discriminator()
	return []any{
		map[string]any{"dataSize": releaseentry.Len},
		map[string]any{
			"memcmp": map[string]any{
				"offset": 0,
				"bytes":  primitives.EncodeBase58(discriminator[:]),
			},
		},
		map[string]any{
			"memcmp": map[string]any{
				"offset": releaseEntryAppIDOffset,
				"bytes":  primitives.EncodeBase58(appID[:]),
			},
		},
	}
}

func (c *storeRPCReader) getProgramAccountsByAppID(ctx context.Context, appID [32]byte) ([]programAccount, error) {
	req := storeRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getProgramAccounts",
		Params: []any{
			licenseRegistryProgramID().Base58(),
			map[string]any{
				"encoding":   "base64",
				"commitment": "confirmed",
				"filters":    releaseEntryByAppIDFilters(appID),
			},
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verify.ErrRPCUnreachable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: HTTP %d: %s", verify.ErrRPCUnreachable, resp.StatusCode, string(raw))
	}
	var parsed storeProgramAccountsResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode getProgramAccounts response: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	out := make([]programAccount, 0, len(parsed.Result))
	for _, item := range parsed.Result {
		if len(item.Account.Data) < 2 || item.Account.Data[1] != "base64" {
			return nil, errors.New("unexpected getProgramAccounts data shape")
		}
		decoded, err := base64.StdEncoding.DecodeString(item.Account.Data[0])
		if err != nil {
			return nil, fmt.Errorf("base64 decode %s: %w", item.Pubkey, err)
		}
		out = append(out, programAccount{Pubkey: item.Pubkey, Data: decoded})
	}
	return out, nil
}

type storeRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type storeRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type storeProgramAccountsResponse struct {
	Result []struct {
		Pubkey  string `json:"pubkey"`
		Account struct {
			Data []string `json:"data"`
		} `json:"account"`
	} `json:"result"`
	Error *storeRPCError `json:"error,omitempty"`
}

// readReleaseEntryMeta decodes the exact ReleaseEntry account the program
// writes (internal/releaseentry.Decode): the Anchor discriminator, exactly
// ReleaseEntry::LEN bytes, every field in declaration order, closed status
// and revoked_at Option tags, and zero padding after the last field. Nothing
// is skipped: the publish admission reads release_hash, the publisher key,
// its signature and the registering vault; the recall projection reads
// revoked_at (a missing or unknown Option tag is refused, never read as None).
func readReleaseEntryMeta(data []byte) (releaseEntryMeta, error) {
	entry, err := releaseentry.Decode(data)
	if err != nil {
		return releaseEntryMeta{}, err
	}
	return releaseEntryMetaFromEntry(entry), nil
}

// readInstallerReleaseEntryMeta decodes the exact K3 account layout
// (internal/installerrelease): discriminator, LEN bytes, every field. The
// pre-K3 layout, which carried no publisher binding, is refused by size.
func readInstallerReleaseEntryMeta(data []byte) (installerReleaseMeta, error) {
	entry, err := installerrelease.Decode(data)
	if err != nil {
		return installerReleaseMeta{}, err
	}
	return installerReleaseMeta{Entry: entry}, nil
}

// readStoreReleaseListingMeta decodes the exact current Anchor/Borsh account
// layout from the license-registry program. The program's StoreListingStatus is
// listing-specific (Active=0, Revoked=1, Delisted=2), so use a local decoder
// rather than verify.ReadAuthorizationStatusByte, which knows only the first
// two generic authorization states. Every short, malformed, or unknown-status
// account is refused rather than treated as unlisted.
func readStoreReleaseListingMeta(data []byte) (storeReleaseListingMeta, error) {
	var meta storeReleaseListingMeta
	if len(data) < verify.AccountDiscriminatorLen {
		return meta, errors.New("store_release_listing: discriminator: buffer too short")
	}
	if !bytes.Equal(data[:verify.AccountDiscriminatorLen], accountDiscriminator("StoreReleaseListing")) {
		return meta, errors.New("store_release_listing: discriminator mismatch")
	}
	offset := verify.AccountDiscriminatorLen
	var err error
	if offset, err = copyFixed(data, offset, meta.StoreAuthority[:], "store_release_listing", "store_authority"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.AppHash[:], "store_release_listing", "app_hash"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.ReleaseEntry[:], "store_release_listing", "release_entry"); err != nil {
		return meta, err
	}
	for _, step := range []struct {
		name string
		n    int
	}{
		{"store_cert_fingerprint", 32},
		{"listed_by", 32},
		{"listed_at", 8},
	} {
		if offset, err = skipFixed(data, offset, step.n, "store_release_listing", step.name); err != nil {
			return meta, err
		}
	}
	if offset >= len(data) {
		return meta, errors.New("store_release_listing: status: buffer too short")
	}
	meta.Status = storeListingStatus(data[offset])
	if meta.Status != storeListingStatusActive && meta.Status != storeListingStatusRevoked && meta.Status != storeListingStatusDelisted {
		return meta, fmt.Errorf("store_release_listing: invalid status byte %d", data[offset])
	}
	offset++
	if offset >= len(data) {
		return meta, errors.New("store_release_listing: revoked_at option: buffer too short")
	}
	switch data[offset] {
	case 0:
		offset++
	case 1:
		if offset, err = skipFixed(data, offset+1, 8, "store_release_listing", "revoked_at"); err != nil {
			return meta, err
		}
	default:
		return meta, fmt.Errorf("store_release_listing: revoked_at option tag %d is invalid", data[offset])
	}
	if offset, err = copyFixed(data, offset, meta.StoreDomainHash[:], "store_release_listing", "store_domain_hash"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.OperatorAuthorization[:], "store_release_listing", "operator_authorization"); err != nil {
		return meta, err
	}
	if _, err = skipFixed(data, offset, 1, "store_release_listing", "bump"); err != nil {
		return meta, err
	}
	return meta, nil
}

func skipFixed(data []byte, offset, n int, account, field string) (int, error) {
	if offset+n > len(data) {
		return -1, fmt.Errorf("%s: %s: buffer too short", account, field)
	}
	return offset + n, nil
}

func copyFixed(data []byte, offset int, dst []byte, account, field string) (int, error) {
	if offset+len(dst) > len(data) {
		return -1, fmt.Errorf("%s: %s: buffer too short", account, field)
	}
	copy(dst, data[offset:offset+len(dst)])
	return offset + len(dst), nil
}

// readInt64LE reads a fixed 8-byte little-endian i64 (Borsh/Anchor encoding, e.g.
// an on-chain Clock unix timestamp) at offset, returning the value and the next
// offset. It fails closed when the buffer is too short.
func readInt64LE(data []byte, offset int, account, field string) (int64, int, error) {
	if offset+8 > len(data) {
		return 0, -1, fmt.Errorf("%s: %s: buffer too short", account, field)
	}
	return int64(binary.LittleEndian.Uint64(data[offset : offset+8])), offset + 8, nil
}

func readBorshStringLocal(data []byte, offset int) (string, int, error) {
	if offset+4 > len(data) {
		return "", offset, errors.New("buffer too short for length")
	}
	n := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	if n < 0 || offset+n > len(data) {
		return "", offset, errors.New("buffer too short for string bytes")
	}
	return string(data[offset : offset+n]), offset + n, nil
}
