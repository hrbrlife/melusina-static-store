package main

// Read-only current generation mode reuses the product's signed private-route
// verifier, pinned TLS client, and signed generation decoder. It never loads a
// publisher key or prepares an envelope.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/publishclient"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func runReadCurrentGeneration(o options, stdout io.Writer) error {
	now := time.Now().UTC()
	routeRaw, err := os.ReadFile(o.privateRoute)
	if err != nil {
		return err
	}
	route, err := publishclient.LoadPrivateRoute(o.privateRoute, o.estateProfile, o.estateProfileSHA, o.store, now)
	if err != nil {
		return err
	}
	if route.ExpiresAt.Sub(now) < 120*time.Second {
		return errors.New("current_generation_route_margin_refused")
	}
	profileRaw, err := os.ReadFile(o.estateProfile)
	if err != nil {
		return err
	}
	profile, err := estateprofile.DecodeProfile(profileRaw)
	if err != nil {
		return err
	}
	profileDigest, err := estateprofile.VerifyProfile(profile)
	if err != nil || profileDigest != o.estateProfileSHA || profile.Store.StoreID != o.storeID ||
		o.store != "https://"+profile.Store.RootDomain {
		return errors.New("current_generation_profile_scope_refused")
	}
	destination, err := loadStorePubkey(o.storePubkey)
	if err != nil {
		return err
	}
	operatorKey, err := destination.SignPublicKey()
	if err != nil || primitives.EncodeBase58(operatorKey) != profile.Store.OperatorKey {
		return errors.New("current_generation_operator_refused")
	}
	client, err := publishclient.NewClientPEM(o.store, route.ConnectAddress, route.TLSLeafPEM, o.timeout)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	raw, doc, err := fetchAndVerifyGeneration(ctx, client, o.store, o.storeID, operatorKey)
	if err != nil {
		return err
	}
	if doc.BundleOrigin != o.store || doc.Channel != "stable" || doc.GenerationID < 1 {
		return errors.New("current_generation_signed_scope_refused")
	}
	if after, readErr := os.ReadFile(o.privateRoute); readErr != nil || sha256.Sum256(after) != sha256.Sum256(routeRaw) {
		return errors.New("current_generation_route_changed_during_readback")
	}
	if after, readErr := os.ReadFile(o.estateProfile); readErr != nil || sha256.Sum256(after) != sha256.Sum256(profileRaw) {
		return errors.New("current_generation_profile_changed_during_readback")
	}
	if err := writeNewCurrentGeneration(o.readCurrentOut, raw); err != nil {
		return err
	}
	sum, routeSum := sha256.Sum256(raw), sha256.Sum256(routeRaw)
	observed := time.Now().UTC()
	return json.NewEncoder(stdout).Encode(map[string]any{
		"schema":       "melusina.store-current-generation-readback.v1",
		"generationId": doc.GenerationID, "generationHash": doc.GenerationHash,
		"storeId": o.storeID, "bundleOrigin": doc.BundleOrigin,
		"sha256": hex.EncodeToString(sum[:]), "routeSha256": hex.EncodeToString(routeSum[:]),
		"routeExpiresAt": route.ExpiresAt.Format(time.RFC3339),
		"observedAt":     observed.Format(time.RFC3339Nano),
		"expiresAt":      observed.Add(180 * time.Second).Format(time.RFC3339Nano),
	})
}

func writeNewCurrentGeneration(path string, raw []byte) (err error) {
	if !filepath.IsAbs(path) || len(raw) == 0 || len(raw) > maxRequestBytes {
		return errors.New("current_generation_output_refused")
	}
	parent := filepath.Dir(path)
	info, statErr := os.Lstat(parent)
	resolved, resolveErr := filepath.EvalSymlinks(parent)
	if statErr != nil || resolveErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || resolved != parent {
		return errors.New("current_generation_output_parent_refused")
	}
	f, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if openErr != nil {
		return errors.New("current_generation_output_exists_or_unwritable")
	}
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(raw); err != nil {
		return fmt.Errorf("current_generation_output_write: %w", err)
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}
