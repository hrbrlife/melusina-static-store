// Command store-catalog-read reads a verified Store catalogue and a signed
// pointer over the owner-signed private route used by publication.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/publishclient"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const maxCatalogRead = 1 << 20

type storeGetter interface {
	Get(string) (*http.Response, error)
}

type catalogPointer struct {
	Schema             string `json:"schema"`
	AppID              string `json:"appId"`
	PackageID          string `json:"packageId"`
	Version            string `json:"version"`
	AppHash            string `json:"appHash"`
	ReleaseHash        string `json:"releaseHash"`
	StageID            string `json:"stageId"`
	CatalogSHA256      string `json:"catalogSha256"`
	PreviousAppHash    string `json:"previousAppHash,omitempty"`
	PreviousVersion    string `json:"previousVersion,omitempty"`
	PreviousValidUntil int64  `json:"previousValidUntil,omitempty"`
	ServingDomainHash  string `json:"servingDomainHash"`
	PublishedAt        int64  `json:"publishedAt"`
	OperatorSignature  string `json:"operatorSignature"`
}

type catalogRow struct {
	AppID     string `json:"appId"`
	PackageID string `json:"packageId"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	Attest    struct {
		AppHash     string `json:"appHash"`
		ReleaseHash string `json:"releaseHash"`
	} `json:"attest"`
}

func readResponse(response *http.Response, gateRequired bool) ([]byte, error) {
	defer response.Body.Close()
	gate := response.Header.Get("X-Store-Catalog-Gate")
	if response.StatusCode != http.StatusOK || (gateRequired && gate != "verified") ||
		(!gateRequired && gate != "" && gate != "verified") {
		return nil, errors.New("publisher_store_catalog_not_verified")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxCatalogRead+1))
	if err != nil || len(raw) > maxCatalogRead {
		return nil, errors.New("publisher_store_catalog_read_refused")
	}
	return raw, nil
}

func catalogRowFor(index []byte, appID string) (*catalogRow, error) {
	var document struct {
		Apps []catalogRow `json:"apps"`
	}
	if err := json.Unmarshal(index, &document); err != nil || document.Apps == nil {
		return nil, errors.New("publisher_store_catalog_index_invalid")
	}
	var selected *catalogRow
	for i := range document.Apps {
		if document.Apps[i].AppID == appID {
			if selected != nil {
				return nil, errors.New("publisher_store_catalog_app_duplicate")
			}
			selected = &document.Apps[i]
		}
	}
	return selected, nil
}

func hash32(value string) ([32]byte, error) {
	var out [32]byte
	if len(value) != 64 || value != strings.ToLower(value) {
		return out, errors.New("not-lowercase-sha256")
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return out, err
	}
	copy(out[:], raw)
	return out, nil
}

// pointerMessage is the Store's app_catalog.go message, including both times.
func pointerMessage(p catalogPointer) ([]byte, error) {
	var previous [32]byte
	if p.PreviousAppHash != "" {
		var err error
		previous, err = hash32(p.PreviousAppHash)
		if err != nil {
			return nil, err
		}
	}
	hashes := [][32]byte{sha256.Sum256([]byte(p.AppID)), sha256.Sum256([]byte(p.PackageID)), sha256.Sum256([]byte(p.Version))}
	for _, value := range []string{p.AppHash, p.ReleaseHash, p.StageID, p.CatalogSHA256} {
		digest, err := hash32(value)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, digest)
	}
	hashes = append(hashes, sha256.Sum256([]byte(p.PreviousVersion)), previous)
	domain, err := hash32(p.ServingDomainHash)
	if err != nil {
		return nil, err
	}
	hashes = append(hashes, domain)
	message := []byte("melusina-app-catalog-pointer-v1\x00")
	for _, digest := range hashes {
		message = append(message, digest[:]...)
	}
	var times [16]byte
	binary.BigEndian.PutUint64(times[:8], uint64(p.PublishedAt))
	binary.BigEndian.PutUint64(times[8:], uint64(p.PreviousValidUntil))
	return append(message, times[:]...), nil
}

func verifyPointer(raw, index []byte, row catalogRow, appID, operator, domain string) error {
	var p catalogPointer
	if err := json.Unmarshal(raw, &p); err != nil {
		return errors.New("publisher_store_pointer_invalid")
	}
	indexHash := sha256.Sum256(index)
	domainHash := primitives.StoreDomainHash(domain)
	if p.Schema != "melusina-app-catalog-pointer-v1" || p.AppID != appID || row.AppID != appID ||
		p.PackageID == "" || p.PackageID != row.PackageID || p.Version == "" || p.Version != row.Version ||
		p.AppHash == "" || p.AppHash != row.Attest.AppHash || p.ReleaseHash == "" || p.ReleaseHash != row.Attest.ReleaseHash ||
		p.CatalogSHA256 != hex.EncodeToString(indexHash[:]) || p.ServingDomainHash != hex.EncodeToString(domainHash[:]) ||
		len(row.SHA256) != 64 || row.SHA256[:32] != p.PackageID || p.PublishedAt <= 0 || p.PreviousValidUntil < 0 {
		return errors.New("publisher_store_pointer_binding_refused")
	}
	key, err := primitives.DecodeBase58(operator)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("publisher_store_pointer_operator_invalid")
	}
	signature, err := primitives.DecodeBase58(p.OperatorSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("publisher_store_pointer_signature_invalid")
	}
	message, err := pointerMessage(p)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), message, signature) {
		return errors.New("publisher_store_pointer_signature_invalid")
	}
	return nil
}

func readCatalog(client storeGetter, origin, path, operator, domain string) ([]byte, error) {
	root := strings.TrimRight(origin, "/")
	indexResponse, err := client.Get(root + "/apps/index.json")
	if err != nil {
		return nil, err
	}
	index, err := readResponse(indexResponse, true)
	if err != nil {
		return nil, err
	}
	if path == "/apps/index.json" {
		return index, nil
	}
	appID := strings.TrimSuffix(strings.TrimPrefix(path, "/apps/pointers/"), ".json")
	row, err := catalogRowFor(index, appID)
	if err != nil {
		return nil, err
	}
	response, err := client.Get(root + path)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusNotFound {
		_ = response.Body.Close()
		if row == nil {
			return nil, nil
		}
		return nil, errors.New("publisher_store_pointer_missing_for_catalog_row")
	}
	raw, err := readResponse(response, false)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, errors.New("publisher_store_pointer_foreign_app")
	}
	if err := verifyPointer(raw, index, *row, appID, operator, domain); err != nil {
		return nil, err
	}
	return raw, nil
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("store-catalog-read", flag.ContinueOnError)
	store := flags.String("store", "", "signed HTTPS Store origin")
	routePath := flags.String("private-route", "", "finalized owner-signed Store transport")
	profilePath := flags.String("estate-profile", "", "owner-signed estate profile")
	profileSHA := flags.String("estate-profile-sha256", "", "reviewed profile digest")
	requestPath := flags.String("path", "/apps/index.json", "verified catalog index or one app pointer")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *store == "" || *routePath == "" || *profilePath == "" || *profileSHA == "" {
		return errors.New("publisher_private_route_arguments_refused")
	}
	if *requestPath != "/apps/index.json" && !(strings.HasPrefix(*requestPath, "/apps/pointers/") && strings.HasSuffix(*requestPath, ".json") && !strings.Contains(strings.TrimPrefix(*requestPath, "/apps/pointers/"), "/")) {
		return errors.New("publisher_store_catalog_path_refused")
	}
	route, err := publishclient.LoadPrivateRoute(*routePath, *profilePath, *profileSHA, *store, time.Now().UTC())
	if err != nil {
		return err
	}
	profileBytes, err := os.ReadFile(*profilePath)
	if err != nil {
		return errors.New("publisher_private_route_profile_refused")
	}
	profile, err := estateprofile.DecodeProfile(profileBytes)
	if err != nil {
		return errors.New("publisher_private_route_profile_refused")
	}
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil || digest != *profileSHA || profile.Store.RootDomain != route.StoreHostname {
		return errors.New("publisher_private_route_profile_refused")
	}
	client, err := publishclient.NewClientPEM(*store, route.ConnectAddress, route.TLSLeafPEM, 25*time.Second)
	if err != nil {
		return err
	}
	raw, err := readCatalog(client, *store, *requestPath, profile.Store.OperatorKey, route.StoreHostname)
	if err != nil {
		return err
	}
	_, err = out.Write(raw)
	return err
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "store-catalog-read:", err)
		os.Exit(1)
	}
}
