package main

// Loader for fleet/bazaar-catalog.yaml — the complete snapshot of the one
// default Bazaar. It keys the rail on the IMMUTABLE appId (never a source-dir
// name, publish slug, or catalog display name, all three of which legitimately
// differ). We deliberately do NOT pull in a general YAML dependency: the
// manifest has one fixed, 2-space-indented shape (groups -> <group> -> apps ->
// <app> -> scalar fields), so a small targeted parser reads exactly that
// structure and rejects anything else. The manifest path comes from
// MEL_RELEASE_CONFIG (env-only config).

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// App is one default-Bazaar catalog entry. AppID is the sole identity;
// Slug/CatalogName/SourcePath are descriptive and may all differ from each
// other and from AppID. SourceCommit, when set, pins the source checkout that
// the provider may build after the entry is explicitly ready.
type App struct {
	Group                  string
	Name                   string
	AppID                  string
	SourcePath             string
	SourceCommit           string
	SourceRepository       string
	PublishSlug            string
	CatalogName            string
	CatalogDeveloper       string
	CatalogRepo            string
	CatalogSlug            string
	PackProfile            string
	Role                   string
	Audience               string
	InstallMode            string
	PearlRole              string
	ClientAccess           string
	AdminSurface           string
	LiveVersion            string
	ReconciliationState    string
	SourceSelectionState   string
	SourceSelectionReceipt string
	ReleaseState           string
}

// Catalog is the closed, complete default-Bazaar snapshot. It is deliberately
// not a local package scan or a smaller release subset.
type Catalog struct {
	Schema                      string
	Origin                      string
	ExpectedLiveAppCount        int
	DefaultReleaseState         string
	DefaultReconciliationState  string
	DefaultSourceSelectionState string
	InstallationPolicyVersion   int
	ReleaseSquadsAuthority      SquadsAuthority
	Apps                        []App
}

// SquadsAuthority is the one publisher authority for the whole default Bazaar.
// It is deliberately catalog-level: apps retain their own SPK keys, but an app
// may never choose a different multisig, vault, or Squads program at release
// time.
type SquadsAuthority struct {
	Multisig    string
	Vault       string
	ProgramID   string
	Threshold   int
	MemberCount int
}

const (
	namedCoinAppID            = "8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh"
	namedCoinMSBDevnetProfile = "namedcoin-msb-devnet"
	// Claude-Melusina embeds Claude Code and its shared-library closure inside
	// the signed SPK. That ~100 MB archive is deliberately untracked, so the
	// build needs it handed in; this reviewed profile is the only sanctioned
	// way. The provider accepts the archive for this appId alone and only when
	// its digest equals the pin tracked in the app source. The CLI enforces the
	// same appId binding here so a catalog edit cannot point another app at it.
	claudeMelusinaAppID                  = "svky21qh5k95fg96zzkpvfcjxncq6z1mkmgguchcdpq8as0km90h"
	claudeMelusinaPackagedRuntimeProfile = "claude-melusina-packaged-runtime"
	defaultBazaarOrigin                  = "https://bazaar.melusina-os.org"
	bazaarCatalogSchema                  = "melusina-bazaar-catalog/v1"
	defaultSquadsMultisig                = "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"
	defaultSquadsVault                   = "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3"
	defaultSquadsProgramID               = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
	defaultSquadsThreshold               = 3
	defaultSquadsMemberCount             = 4
	installationPolicyVersion            = 1
)

// LoadCatalog parses the manifest at path. The manifest has one fixed shape
// (2-space indentation: groups -> <group> -> apps -> <app> -> scalar fields).
// The parser is deliberately targeted rather than a general YAML dependency, but
// it FAILS CLOSED: inside an `apps:` block — the ONLY region where a silently
// dropped line would drop an app or an app field — any line that does not match an
// expected production is an error, and a tab in a line's indentation (which YAML
// forbids and which would corrupt this space-based indent detection, silently
// re-homing the line to column 0) is an error anywhere. Descriptive material
// OUTSIDE the apps blocks is intentionally ignored after the required catalog
// snapshot fields have been parsed.
func LoadCatalog(path string) (*Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Bazaar catalog manifest: %w", err)
	}
	defer f.Close()

	const (
		groupIndent = 2
		appsIndent  = 4
		appIndent   = 6
		fieldIndent = 8
	)
	catalog := &Catalog{}
	var (
		inGroups                 bool
		inReleaseSquadsAuthority bool
		curGroup                 string
		inApps                   bool
		curApp                   *App
	)
	flush := func() {
		if curApp != nil {
			catalog.Apps = append(catalog.Apps, *curApp)
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
			return nil, fmt.Errorf("Bazaar catalog manifest %s line %d: tab in indentation is not allowed: %q", path, lineNo, raw)
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
		if inReleaseSquadsAuthority {
			if indent == 0 {
				inReleaseSquadsAuthority = false
			} else {
				if indent != groupIndent || !hasVal {
					return nil, fmt.Errorf("Bazaar catalog manifest %s line %d: malformed release_squads_authority entry %q", path, lineNo, strings.TrimSpace(raw))
				}
				if err := assignReleaseSquadsAuthority(&catalog.ReleaseSquadsAuthority, key, unquote(val), path, lineNo); err != nil {
					return nil, err
				}
				continue
			}
		}

		// Dedent: a line below the app-field column closes the current app; a
		// column-0 line closes the group scope entirely.
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
			catalog.Schema = unquote(val)
		case indent == 0 && key == "catalog_origin":
			catalog.Origin = unquote(val)
		case indent == 0 && key == "expected_live_app_count":
			count, err := strconv.Atoi(unquote(val))
			if err != nil || count < 1 {
				return nil, fmt.Errorf("Bazaar catalog manifest %s line %d: expected_live_app_count must be a positive integer", path, lineNo)
			}
			catalog.ExpectedLiveAppCount = count
		case indent == 0 && key == "default_release_state":
			catalog.DefaultReleaseState = unquote(val)
		case indent == 0 && key == "default_reconciliation_state":
			catalog.DefaultReconciliationState = unquote(val)
		case indent == 0 && key == "default_source_selection_state":
			catalog.DefaultSourceSelectionState = unquote(val)
		case indent == 0 && key == "installation_policy_version":
			version, err := strconv.Atoi(unquote(val))
			if err != nil || version != installationPolicyVersion {
				return nil, fmt.Errorf("Bazaar catalog manifest %s line %d: installation_policy_version must be %d", path, lineNo, installationPolicyVersion)
			}
			catalog.InstallationPolicyVersion = version
		case indent == 0 && key == "release_squads_authority":
			if hasVal {
				return nil, fmt.Errorf("Bazaar catalog manifest %s line %d: release_squads_authority must be a mapping", path, lineNo)
			}
			inReleaseSquadsAuthority = true
		case indent == 0 && key == "groups":
			inGroups = true
		case indent == 0:
			// Snapshot evidence not needed by the CLI (observed timestamp and index
			// checksum) remains in the manifest for humans and external audit.
		case !inGroups:
			// Top-level descriptive block bodies are intentionally ignored.
		case indent == groupIndent && !hasVal:
			// New catalog group header.
			flush()
			curGroup = key
			inApps = false
		case indent == appsIndent && key == "apps":
			inApps = true
		case indent == appsIndent:
			// A group-level block header other than apps — leave the
			// apps scope; its body is ignored by the !inApps arm below.
			flush()
			inApps = false
		case !inApps:
			// Group-level block body below a non-apps
			// header — intentionally ignored.
		case indent == appIndent && !hasVal:
			// New app header inside apps:.
			flush()
			curApp = &App{Group: curGroup, Name: key}
		case indent == fieldIndent && curApp != nil && hasVal:
			if err := assignAppField(curApp, key, unquote(val)); err != nil {
				return nil, fmt.Errorf("Bazaar catalog manifest %s line %d: %w", path, lineNo, err)
			}
		default:
			// Inside an apps: block but matching no expected production: a
			// mis-indented or reshaped line that would otherwise silently drop an
			// app or a field. Fail closed.
			return nil, fmt.Errorf("Bazaar catalog manifest %s line %d: unexpected line inside the %q apps block (indent %d): %q", path, lineNo, curGroup, indent, strings.TrimSpace(raw))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()

	if catalog.Schema != bazaarCatalogSchema {
		return nil, fmt.Errorf("Bazaar catalog manifest %s has schema %q, want %q", path, catalog.Schema, bazaarCatalogSchema)
	}
	if catalog.Origin != defaultBazaarOrigin {
		return nil, fmt.Errorf("Bazaar catalog manifest %s has origin %q, want %q", path, catalog.Origin, defaultBazaarOrigin)
	}
	if catalog.ExpectedLiveAppCount < 1 {
		return nil, fmt.Errorf("Bazaar catalog manifest %s has no expected_live_app_count", path)
	}
	if !validReleaseState(catalog.DefaultReleaseState) {
		return nil, fmt.Errorf("Bazaar catalog manifest %s has invalid default_release_state %q", path, catalog.DefaultReleaseState)
	}
	if strings.TrimSpace(catalog.DefaultReconciliationState) == "" {
		return nil, fmt.Errorf("Bazaar catalog manifest %s has no default_reconciliation_state", path)
	}
	if catalog.DefaultSourceSelectionState == "" {
		// An older manifest stays safely non-releasable until it names a reviewed
		// source decision. This is an additive migration, not a bypass for a
		// historical ready entry.
		catalog.DefaultSourceSelectionState = "pending"
	}
	if !validSourceSelectionState(catalog.DefaultSourceSelectionState) {
		return nil, fmt.Errorf("Bazaar catalog manifest %s has invalid default_source_selection_state %q", path, catalog.DefaultSourceSelectionState)
	}
	if len(catalog.Apps) != catalog.ExpectedLiveAppCount {
		return nil, fmt.Errorf("Bazaar catalog manifest %s names %d apps, want expected_live_app_count %d", path, len(catalog.Apps), catalog.ExpectedLiveAppCount)
	}
	// Older already-governed manifests did not spell out quorum fields. Their
	// only supported meaning is the Bazaar-wide fixed 3-of-4 policy; normalize
	// that representation before validation. Any explicit alternate value still
	// fails closed below.
	if catalog.ReleaseSquadsAuthority.Threshold == 0 {
		catalog.ReleaseSquadsAuthority.Threshold = defaultSquadsThreshold
	}
	if catalog.ReleaseSquadsAuthority.MemberCount == 0 {
		catalog.ReleaseSquadsAuthority.MemberCount = defaultSquadsMemberCount
	}
	// Fail closed on a malformed identity.
	seen := map[string]bool{}
	for index := range catalog.Apps {
		a := &catalog.Apps[index]
		if a.ReleaseState == "" {
			a.ReleaseState = catalog.DefaultReleaseState
		}
		if a.ReconciliationState == "" {
			a.ReconciliationState = catalog.DefaultReconciliationState
		}
		if a.SourceSelectionState == "" {
			a.SourceSelectionState = catalog.DefaultSourceSelectionState
		}
		if strings.TrimSpace(a.AppID) == "" {
			return nil, fmt.Errorf("catalog app %q/%q has no appId", a.Group, a.Name)
		}
		if strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Group) == "" || strings.TrimSpace(a.PublishSlug) == "" || strings.TrimSpace(a.CatalogName) == "" || strings.TrimSpace(a.LiveVersion) == "" || strings.TrimSpace(a.CatalogDeveloper) == "" || strings.TrimSpace(a.CatalogRepo) == "" || strings.TrimSpace(a.CatalogSlug) == "" || strings.TrimSpace(a.SourceRepository) == "" || strings.TrimSpace(a.Role) == "" {
			return nil, fmt.Errorf("catalog app %q is missing required catalog identity or live snapshot data", a.AppID)
		}
		if !validCanonicalSourceRepository(a.SourceRepository) {
			return nil, fmt.Errorf("catalog app %q has invalid source_repository %q", a.AppID, a.SourceRepository)
		}
		if seen[a.AppID] {
			return nil, fmt.Errorf("duplicate appId %q in Bazaar catalog", a.AppID)
		}
		if !validReleaseState(a.ReleaseState) {
			return nil, fmt.Errorf("catalog app %q has invalid release_state %q", a.AppID, a.ReleaseState)
		}
		if strings.TrimSpace(a.ReconciliationState) == "" {
			return nil, fmt.Errorf("catalog app %q has no reconciliation_state", a.AppID)
		}
		if !validSourceSelectionState(a.SourceSelectionState) {
			return nil, fmt.Errorf("catalog app %q has invalid source_selection_state %q", a.AppID, a.SourceSelectionState)
		}
		// Legacy synthetic fixtures stay readable until they opt into the
		// installation-policy version. The checked-in default Bazaar opts in and
		// therefore cannot silently lose a mode, audience, or authority surface.
		if catalog.InstallationPolicyVersion == installationPolicyVersion && !validInstallationPolicy(*a) {
			return nil, fmt.Errorf("catalog app %q has missing or invalid installation policy", a.AppID)
		}
		if a.ReleaseState == "ready" && (strings.TrimSpace(a.SourcePath) == "" || strings.TrimSpace(a.SourceCommit) == "") {
			return nil, fmt.Errorf("ready catalog app %q must declare source_path and source_commit", a.AppID)
		}
		if a.ReleaseState == "ready" && (!sourceSelectionReady(a.SourceSelectionState) || strings.TrimSpace(a.SourceSelectionReceipt) == "") {
			return nil, fmt.Errorf("ready catalog app %q must declare a reviewed source selection receipt", a.AppID)
		}
		if a.PackProfile != "" && !reviewedPackProfile(a.AppID, a.PackProfile) {
			return nil, fmt.Errorf("app %q has unsupported pack_profile %q; only NamedCoin may declare %q and only Claude-Melusina may declare %q", a.AppID, a.PackProfile, namedCoinMSBDevnetProfile, claudeMelusinaPackagedRuntimeProfile)
		}
		if a.SourceCommit != "" && !isLowerHexCommit(a.SourceCommit) {
			return nil, fmt.Errorf("app %q has invalid source_commit %q; want a lowercase 40-hex commit", a.AppID, a.SourceCommit)
		}
		seen[a.AppID] = true
	}
	if !validSquadsAuthority(catalog.ReleaseSquadsAuthority) {
		return nil, fmt.Errorf("Bazaar catalog manifest %s has an incomplete or malformed release_squads_authority", path)
	}
	return catalog, nil
}

// Select resolves a selector to exactly one app. It matches, in priority order,
// the immutable appId, then the publish slug, then the app name, then the catalog
// name — always requiring a unique hit so an ambiguous selector fails closed.
func (c *Catalog) Select(selector string) (App, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return App{}, fmt.Errorf("empty app selector")
	}
	for _, a := range c.Apps {
		if a.AppID == selector {
			return a, nil
		}
	}
	var hits []App
	for _, a := range c.Apps {
		if a.PublishSlug == selector || a.Name == selector || a.CatalogName == selector {
			hits = append(hits, a)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return App{}, fmt.Errorf("no app in the Bazaar catalog matches selector %q", selector)
	default:
		return App{}, fmt.Errorf("selector %q is ambiguous across %d apps — use the immutable appId", selector, len(hits))
	}
}

// RequireReleaseReady prevents a complete catalog snapshot from becoming a
// way to publish an unresolved entry. The catalog defaults new or incomplete
// entries to hold; a publishable app must explicitly carry its reviewed source
// selection and ready release state.
func (a App) RequireReleaseReady() error {
	if a.ReleaseState != "ready" {
		return fmt.Errorf("app %q (%s) is held for reconciliation (%s)", a.Name, a.AppID, a.ReconciliationState)
	}
	if !sourceSelectionReady(a.SourceSelectionState) || strings.TrimSpace(a.SourceSelectionReceipt) == "" {
		return fmt.Errorf("app %q (%s) is held for source selection (%s)", a.Name, a.AppID, a.SourceSelectionState)
	}
	return nil
}

func validReleaseState(value string) bool {
	return value == "hold" || value == "ready"
}

func validSourceSelectionState(value string) bool {
	return value == "pending" || value == "direct-dev-verified" || value == "prepublish-integrated"
}

func sourceSelectionReady(value string) bool {
	return value == "direct-dev-verified" || value == "prepublish-integrated"
}

func assignAppField(a *App, key, val string) error {
	switch key {
	case "appId":
		a.AppID = val
	case "source_path":
		a.SourcePath = val
	case "source_commit":
		a.SourceCommit = val
	case "source_repository":
		a.SourceRepository = val
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
	case "audience":
		a.Audience = val
	case "install_mode":
		a.InstallMode = val
	case "pearl_role":
		a.PearlRole = val
	case "client_access":
		a.ClientAccess = val
	case "admin_surface":
		a.AdminSurface = val
	case "live_version":
		a.LiveVersion = val
	case "reconciliation_state":
		a.ReconciliationState = val
	case "source_selection_state":
		a.SourceSelectionState = val
	case "source_selection_receipt":
		a.SourceSelectionReceipt = val
	case "release_state":
		a.ReleaseState = val
	case "release_squads_authority", "squads_authority", "squads_multisig", "squads_vault", "squads_program_id", "publisher_squads_vault":
		return fmt.Errorf("app %q may not declare app-specific Squads authority field %q", a.Name, key)
	}
	return nil
}

func validInstallationPolicy(app App) bool {
	return validInstallationAudience(app.Audience) &&
		validInstallationMode(app.InstallMode) &&
		validPearlRole(app.PearlRole) &&
		validClientAccess(app.ClientAccess) &&
		validAdminSurface(app.AdminSurface)
}

func validInstallationAudience(value string) bool {
	switch value {
	case "foundation", "operator", "client", "workspace", "engineering":
		return true
	default:
		return false
	}
}

func validInstallationMode(value string) bool {
	switch value {
	case "owner-only", "owner-provisions", "self-service":
		return true
	default:
		return false
	}
}

func validPearlRole(value string) bool {
	switch value {
	case "authority", "proxy", "workflow", "workspace", "template", "test":
		return true
	default:
		return false
	}
}

func validClientAccess(value string) bool {
	switch value {
	case "none", "scoped-share", "self-owned":
		return true
	default:
		return false
	}
}

func validAdminSurface(value string) bool {
	switch value {
	case "hidden-authority", "same-pearl", "deployment-only":
		return true
	default:
		return false
	}
}

func assignReleaseSquadsAuthority(authority *SquadsAuthority, key, value, path string, lineNo int) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("Bazaar catalog manifest %s line %d: release_squads_authority.%s must not be empty", path, lineNo, key)
	}
	switch key {
	case "multisig":
		if authority.Multisig != "" {
			return fmt.Errorf("Bazaar catalog manifest %s line %d: duplicate release_squads_authority.%s", path, lineNo, key)
		}
		authority.Multisig = value
	case "vault":
		if authority.Vault != "" {
			return fmt.Errorf("Bazaar catalog manifest %s line %d: duplicate release_squads_authority.%s", path, lineNo, key)
		}
		authority.Vault = value
	case "program_id":
		if authority.ProgramID != "" {
			return fmt.Errorf("Bazaar catalog manifest %s line %d: duplicate release_squads_authority.%s", path, lineNo, key)
		}
		authority.ProgramID = value
	case "threshold", "member_count":
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			return fmt.Errorf("Bazaar catalog manifest %s line %d: release_squads_authority.%s must be a positive integer", path, lineNo, key)
		}
		if key == "threshold" {
			if authority.Threshold != 0 {
				return fmt.Errorf("Bazaar catalog manifest %s line %d: duplicate release_squads_authority.%s", path, lineNo, key)
			}
			authority.Threshold = parsed
		} else {
			if authority.MemberCount != 0 {
				return fmt.Errorf("Bazaar catalog manifest %s line %d: duplicate release_squads_authority.%s", path, lineNo, key)
			}
			authority.MemberCount = parsed
		}
	default:
		return fmt.Errorf("Bazaar catalog manifest %s line %d: unknown release_squads_authority field %q", path, lineNo, key)
	}
	return nil
}

func validSquadsAuthority(authority SquadsAuthority) bool {
	return authority.Multisig == defaultSquadsMultisig &&
		authority.Vault == defaultSquadsVault &&
		authority.ProgramID == defaultSquadsProgramID &&
		authority.Threshold == defaultSquadsThreshold &&
		authority.MemberCount == defaultSquadsMemberCount
}

func isLowerHexCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func validCanonicalSourceRepository(value string) bool {
	const prefix = "https://github.com/hrbrlife/"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(value, prefix), ".git")
	if name == "" || strings.Contains(name, "/") {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
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
// continuation lines as groups/apps.
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

// reviewedPackProfile reports whether a non-default package recipe is one of
// the reviewed, appId-bound profiles. A profile is never a free-form string
// an operator can attach to any app: each one names exactly one app identity.
func reviewedPackProfile(appID, profile string) bool {
	switch profile {
	case namedCoinMSBDevnetProfile:
		return appID == namedCoinAppID
	case claudeMelusinaPackagedRuntimeProfile:
		return appID == claudeMelusinaAppID
	}
	return false
}
