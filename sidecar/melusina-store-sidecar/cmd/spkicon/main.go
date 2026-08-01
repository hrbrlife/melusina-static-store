// Command spkicon extracts each published app's own market icon from the .spk
// bytes in a catalog and writes them as an appId-keyed asset set the store SPA
// serves at /icons/app/<appId>.<ext>.
//
// It reads a catalog laid out the way the sidecar assembles one:
//
//	<catalog>/apps/index.json          -> appId + packageId per app
//	<catalog>/packages/<packageId>     -> the .spk those bytes were published as
//
// Usage:
//
//	spkicon -catalog <dir> -out <dir> [-manifest <file>]
//
// This is read-only over the catalog. It never writes into it, and it is not on
// the publish path — internal/spkicon is the shared library, so what this emits
// is byte-identical to what the sidecar extracts at publish time.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/hrbrlife/melusina-store-sidecar/internal/spkicon"
)

type catalogIndex struct {
	Apps []struct {
		AppID     string `json:"appId"`
		PackageID string `json:"packageId"`
		Name      string `json:"name"`
	} `json:"apps"`
}

// manifestEntry records what was emitted for one app, so a build can prove which
// apps have a real icon and which fall back to the SPA's generated letter tile.
type manifestEntry struct {
	AppID string `json:"appId"`
	Name  string `json:"name"`
	File  string `json:"file,omitempty"`
	Bytes int    `json:"bytes,omitempty"`
	Note  string `json:"note,omitempty"`
}

func main() {
	catalogDir := flag.String("catalog", "", "catalog root containing apps/index.json and packages/")
	outDir := flag.String("out", "", "directory to write <appId>.<ext> icons into")
	manifestPath := flag.String("manifest", "", "optional path to write a JSON coverage manifest")
	mapPath := flag.String("map", "", "optional path to write the appId -> filename map the SPA imports")
	flag.Parse()

	if *catalogDir == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "spkicon: -catalog and -out are both required")
		os.Exit(2)
	}
	if err := run(*catalogDir, *outDir, *manifestPath, *mapPath); err != nil {
		fmt.Fprintf(os.Stderr, "spkicon: %v\n", err)
		os.Exit(1)
	}
}

func run(catalogDir, outDir, manifestPath, mapPath string) error {
	indexBytes, err := os.ReadFile(filepath.Join(catalogDir, "apps", "index.json"))
	if err != nil {
		return fmt.Errorf("read catalog index: %w", err)
	}
	var index catalogIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return fmt.Errorf("decode catalog index: %w", err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}

	var (
		entries   []manifestEntry
		extracted int
		skipped   int
	)
	iconMap := map[string]string{}
	for _, app := range index.Apps {
		if app.AppID == "" || app.PackageID == "" {
			skipped++
			entries = append(entries, manifestEntry{AppID: app.AppID, Name: app.Name, Note: "index row has no appId/packageId"})
			continue
		}
		spkBytes, err := os.ReadFile(filepath.Join(catalogDir, "packages", app.PackageID))
		if err != nil {
			skipped++
			entries = append(entries, manifestEntry{AppID: app.AppID, Name: app.Name, Note: "package bytes unavailable"})
			continue
		}
		icon, err := spkicon.Extract(spkBytes)
		if err != nil {
			// A package with no icon is legitimate; only surface it as coverage.
			note := "no icon in package"
			if !errors.Is(err, spkicon.ErrNoIcon) {
				note = err.Error()
			}
			skipped++
			entries = append(entries, manifestEntry{AppID: app.AppID, Name: app.Name, Note: note})
			continue
		}
		name := app.AppID + "." + icon.Ext
		if err := os.WriteFile(filepath.Join(outDir, name), icon.Data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		extracted++
		iconMap[app.AppID] = name
		entries = append(entries, manifestEntry{AppID: app.AppID, Name: app.Name, File: name, Bytes: len(icon.Data)})
	}

	if mapPath != "" {
		// The SPA imports this map so it can request one exact icon URL per app.
		// Probing extensions instead would fire a 404 for every png app and paint
		// the letter tile mid-flight — the flicker this whole path removes.
		out, err := json.MarshalIndent(iconMap, "", "  ")
		if err != nil {
			return fmt.Errorf("encode icon map: %w", err)
		}
		if err := os.WriteFile(mapPath, append(out, '\n'), 0o644); err != nil {
			return fmt.Errorf("write icon map: %w", err)
		}
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	if manifestPath != "" {
		out, err := json.MarshalIndent(struct {
			Extracted int             `json:"extracted"`
			Skipped   int             `json:"skipped"`
			Apps      []manifestEntry `json:"apps"`
		}{extracted, skipped, entries}, "", "  ")
		if err != nil {
			return fmt.Errorf("encode manifest: %w", err)
		}
		if err := os.WriteFile(manifestPath, append(out, '\n'), 0o644); err != nil {
			return fmt.Errorf("write manifest: %w", err)
		}
	}
	fmt.Printf("spkicon: extracted %d, skipped %d, of %d apps\n", extracted, skipped, len(index.Apps))
	return nil
}
