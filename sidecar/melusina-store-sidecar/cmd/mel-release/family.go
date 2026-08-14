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
	Family           string
	Name             string
	AppID            string
	SourcePath       string
	PublishSlug      string
	CatalogName      string
	CatalogDeveloper string
	CatalogRepo      string
	CatalogSlug      string
	PackProfile      string
	Role             string
}

// Family is the closed set of apps explicitly declared by one manifest.
type Family struct {
	Schema string
	Apps   []App
}

const (
	namedCoinAppID            = "8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh"
	namedCoinMSBDevnetProfile = "namedcoin-msb-devnet"
)

// LoadFamily parses the manifest at path. The manifest has one fixed shape
// (2-space indentation: families -> <family> -> apps -> <app> -> scalar fields).
// The parser is deliberately targeted rather than a general YAML dependency, but
// it FAILS CLOSED: inside an `apps:` block — the ONLY region where a silently
// dropped line would drop an app or an app field — any line that does not match an
// expected production is an error, and a tab in a line's indentation (which YAML
// forbids and which would corrupt this space-based indent detection, silently
// re-homing the line to column 0) is an error anywhere. Descriptive material
// OUTSIDE the apps blocks (the schema preamble, the env:/defaults: blocks,
// family-level squads: bodies, and the trailing closure keys including the folded
// `out_of_scope_note` block scalar) is intentionally ignored.
func LoadFamily(path string) (*Family, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open release-family manifest: %w", err)
	}
	defer f.Close()

	const (
		familyIndent = 2
		appsIndent   = 4
		appIndent    = 6
		fieldIndent  = 8
	)
	fam := &Family{}
	var (
		inFamilies bool
		curFamily  string
		inApps     bool
		curApp     *App
	)
	flush := func() {
		if curApp != nil {
			fam.Apps = append(fam.Apps, *curApp)
			curApp = nil
		}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	blockIndent := -1 // when >= 0, skip a `key: >`/`key: |` block-scalar body indented > this
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		if hasTabInIndent(raw) {
			return nil, fmt.Errorf("release-family manifest %s line %d: tab in indentation is not allowed: %q", path, lineNo, raw)
		}
		indent := leadingSpaces(line)
		// Consume the indented body of a block scalar (e.g. out_of_scope_note: >).
		if blockIndent >= 0 {
			if indent > blockIndent {
				continue
			}
			blockIndent = -1
		}
		key, val, hasVal := splitKV(strings.TrimSpace(line))
		if hasVal && isBlockScalarIndicator(val) {
			blockIndent = indent
		}

		// Dedent: a line below the app-field column closes the current app; a
		// column-0 line closes the family scope entirely.
		if inApps && indent < appIndent {
			flush()
			inApps = false
		}
		if indent == 0 {
			flush()
			inApps = false
		}

		switch {
		case indent == 0 && key == "schema":
			fam.Schema = unquote(val)
		case indent == 0 && key == "families":
			inFamilies = true
		case indent == 0:
			// Descriptive top-level scalar (frozen, component_class, closed, count,
			// out_of_scope_note, ...) — intentionally ignored.
		case !inFamilies:
			// Pre-families env:/defaults: block bodies — intentionally ignored.
		case indent == familyIndent && !hasVal:
			// New family header.
			flush()
			curFamily = key
			inApps = false
		case indent == appsIndent && key == "apps":
			inApps = true
		case indent == appsIndent:
			// A family-level block header other than apps (e.g. squads:) — leave the
			// apps scope; its body is ignored by the !inApps arm below.
			flush()
			inApps = false
		case !inApps:
			// Family-level block body (squads: children, etc.) below a non-apps
			// header — intentionally ignored.
		case indent == appIndent && !hasVal:
			// New app header inside apps:.
			flush()
			curApp = &App{Family: curFamily, Name: key}
		case indent == fieldIndent && curApp != nil && hasVal:
			assignAppField(curApp, key, unquote(val))
		default:
			// Inside an apps: block but matching no expected production: a
			// mis-indented or reshaped line that would otherwise silently drop an
			// app or a field. Fail closed.
			return nil, fmt.Errorf("release-family manifest %s line %d: unexpected line inside the %q apps block (indent %d): %q", path, lineNo, curFamily, indent, strings.TrimSpace(raw))
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
		if a.PackProfile != "" && (a.AppID != namedCoinAppID || a.PackProfile != namedCoinMSBDevnetProfile) {
			return nil, fmt.Errorf("app %q has unsupported pack_profile %q; only NamedCoin may declare %q", a.AppID, a.PackProfile, namedCoinMSBDevnetProfile)
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
	case "catalog_developer":
		a.CatalogDeveloper = val
	case "catalog_repo":
		a.CatalogRepo = val
	case "catalog_slug":
		a.CatalogSlug = val
	case "pack_profile":
		a.PackProfile = val
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

// hasTabInIndent reports whether the leading whitespace of raw contains a tab.
// YAML forbids tabs for indentation; because this parser measures indentation in
// spaces, a tab would be miscounted (silently re-homing the line to column 0), so
// the loader fails closed on it instead of dropping the line.
func hasTabInIndent(raw string) bool {
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case ' ':
			continue
		case '\t':
			return true
		default:
			return false
		}
	}
	return false
}

// isBlockScalarIndicator reports whether a mapping value is a YAML block-scalar
// header ('>' or '|', optionally followed by a chomping/indentation indicator such
// as '>-', '|+', or '|2'). The manifest uses one (out_of_scope_note: >);
// recognizing it lets the parser skip the indented body rather than misread those
// continuation lines as families/apps.
func isBlockScalarIndicator(v string) bool {
	if v == "" || (v[0] != '>' && v[0] != '|') {
		return false
	}
	for i := 1; i < len(v); i++ {
		if c := v[i]; c != '-' && c != '+' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
