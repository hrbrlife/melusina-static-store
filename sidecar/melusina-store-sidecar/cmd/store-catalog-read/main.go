// Command store-catalog-read reads the verified Store index through the same
// owner-signed private route used by direct app publication.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/publishclient"
)

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
	client, err := publishclient.NewClientPEM(*store, route.ConnectAddress, route.TLSLeafPEM, 25*time.Second)
	if err != nil {
		return err
	}
	response, err := client.Get(strings.TrimRight(*store, "/") + *requestPath)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound && *requestPath != "/apps/index.json" {
		return nil
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Store-Catalog-Gate") != "verified" {
		return errors.New("publisher_store_catalog_not_verified")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return errors.New("publisher_store_catalog_read_refused")
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
