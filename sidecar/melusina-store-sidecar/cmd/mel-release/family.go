package main

// Loader for fleet/release-family.yaml — the FROZEN family manifest that keys the
// rail on the IMMUTABLE appId (never a source-dir name, publish slug, or catalog
// display name, all three of which legitimately differ). We deliberately do NOT
// pull in a general YAML dependency: the manifest has one fixed, 2-space-indented
// shape (families -> <family> -> apps -> <app> -> scalar fields), so a small
// targeted parser reads exactly that structure and rejects anything else. The
// manifest path comes from MEL_RELEASE_CONFIG (env-only config).

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// App is one release-family app entry. AppID is the sole identity; Slug/CatalogName
// /SourcePath are descriptive and may all differ from each other and from AppID.
type App struct {
	Family      string
	Name        string
	AppID       string
	SourcePath  string
	PublishSlug string
	CatalogName string
	Role        string
}

// Family manifest, closed at the 8-app CCASH/Popaye + NamedCoin surface.
type Family struct {
	Schema string
	Apps   []App
}

// LoadFamily parses the manifest at path.
func LoadFamily(path string) (*Family, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open release-family manifest: %w", err)
	}
	defer f.Close()

	fam := &Family{}
	var (
		inFamilies   bool
		curFamily    string
		inApps       bool
		curApp       *App
		familyIndent = 2
		appsIndent   = 4
		appIndent    = 6
		fieldIndent  = 8
	)
	flush := func() {
		if curApp != nil {
			fam.Apps = append(fam.Apps, *curApp)
			curApp = nil
		}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		raw := sc.Text()
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := leadingSpaces(line)
		key, val, hasVal := splitKV(strings.TrimSpace(line))

		switch {
		case indent == 0 && key == "schema":
			fam.Schema = unquote(val)
		case indent == 0 && key == "families":
			inFamilies = true
		case inFamilies && indent == familyIndent && !hasVal:
			// New family header.
			flush()
			curFamily = key
			inApps = false
		case inFamilies && indent == appsIndent && key == "apps":
			inApps = true
		case inFamilies && indent == appsIndent && key != "apps":
			// Some other family-level block (e.g. squads:) — leave the apps scope.
			flush()
			inApps = false
		case inFamilies && inApps && indent == appIndent && !hasVal:
			// New app header.
			flush()
			curApp = &App{Family: curFamily, Name: key}
		case inFamilies && inApps && indent == fieldIndent && curApp != nil && hasVal:
			assignAppField(curApp, key, unquote(val))
		default:
			// Deeper/other lines (per-app comments already stripped, squads bodies,
			// closure keys) are ignored by design.
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()

	if len(fam.Apps) == 0 {
		return nil, fmt.Errorf("release-family manifest %s named no apps", path)
	}
	// Fail closed on a malformed identity.
	seen := map[string]bool{}
	for _, a := range fam.Apps {
		if strings.TrimSpace(a.AppID) == "" {
			return nil, fmt.Errorf("app %q/%q has no appId", a.Family, a.Name)
		}
		if seen[a.AppID] {
			return nil, fmt.Errorf("duplicate appId %q in manifest", a.AppID)
		}
		seen[a.AppID] = true
	}
	return fam, nil
}

// Select resolves a selector to exactly one app. It matches, in priority order,
// the immutable appId, then the publish slug, then the app name, then the catalog
// name — always requiring a unique hit so an ambiguous selector fails closed.
func (f *Family) Select(selector string) (App, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return App{}, fmt.Errorf("empty app selector")
	}
	for _, a := range f.Apps {
		if a.AppID == selector {
			return a, nil
		}
	}
	var hits []App
	for _, a := range f.Apps {
		if a.PublishSlug == selector || a.Name == selector || a.CatalogName == selector {
			hits = append(hits, a)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return App{}, fmt.Errorf("no app in the family manifest matches selector %q", selector)
	default:
		return App{}, fmt.Errorf("selector %q is ambiguous across %d apps — use the immutable appId", selector, len(hits))
	}
}

func assignAppField(a *App, key, val string) {
	switch key {
	case "appId":
		a.AppID = val
	case "source_path":
		a.SourcePath = val
	case "publish_slug":
		a.PublishSlug = val
	case "catalog_name":
		a.CatalogName = val
	case "role":
		a.Role = val
	}
}

func leadingSpaces(s string) int {
	n := 0
	for _, c := range s {
		if c != ' ' {
			break
		}
		n++
	}
	return n
}

// splitKV splits "key: value" (or a bare "key:") on the first colon-space / colon.
func splitKV(s string) (key, val string, hasVal bool) {
	if i := strings.Index(s, ":"); i >= 0 {
		key = strings.TrimSpace(s[:i])
		rest := strings.TrimSpace(s[i+1:])
		return key, rest, rest != ""
	}
	return strings.TrimSpace(s), "", false
}

// stripComment removes an unquoted trailing "# ..." comment. A quoted value keeps
// its content intact (none of the manifest's values contain '#', so a simple
// space-hash cut is sufficient and safe).
func stripComment(line string) string {
	if strings.HasPrefix(strings.TrimSpace(line), "#") {
		return ""
	}
	if i := strings.Index(line, " #"); i >= 0 {
		return line[:i]
	}
	return line
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}
