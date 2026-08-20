package main

import "fmt"

// governedInstallationPolicy is a Store-owned projection. It is deliberately
// not trusted from app metadata: fleet/bazaar-catalog.yaml creates the initial
// row, and later governed app promotions retain the existing validated policy.
type governedInstallationPolicy struct {
	Audience     string
	InstallMode  string
	PearlRole    string
	ClientAccess string
	AdminSurface string
}

func readGovernedInstallationPolicy(raw any, present bool) (governedInstallationPolicy, bool, error) {
	if !present {
		return governedInstallationPolicy{}, false, nil
	}
	if raw == nil {
		return governedInstallationPolicy{}, false, fmt.Errorf("installation policy is null")
	}
	mapping, ok := raw.(map[string]any)
	if !ok {
		return governedInstallationPolicy{}, false, fmt.Errorf("installation policy is not an object")
	}
	read := func(key string) string {
		value, _ := mapping[key].(string)
		return value
	}
	policy := governedInstallationPolicy{
		Audience:     read("audience"),
		InstallMode:  read("install_mode"),
		PearlRole:    read("pearl_role"),
		ClientAccess: read("client_access"),
		AdminSurface: read("admin_surface"),
	}
	if !validGovernedInstallationPolicy(policy) {
		return governedInstallationPolicy{}, false, fmt.Errorf("installation policy has invalid or missing fields")
	}
	return policy, true, nil
}

func (p governedInstallationPolicy) catalogValue() map[string]any {
	return map[string]any{
		"audience":      p.Audience,
		"install_mode":  p.InstallMode,
		"pearl_role":    p.PearlRole,
		"client_access": p.ClientAccess,
		"admin_surface": p.AdminSurface,
	}
}

func validGovernedInstallationPolicy(policy governedInstallationPolicy) bool {
	return validGovernedAudience(policy.Audience) &&
		validGovernedInstallMode(policy.InstallMode) &&
		validGovernedPearlRole(policy.PearlRole) &&
		validGovernedClientAccess(policy.ClientAccess) &&
		validGovernedAdminSurface(policy.AdminSurface)
}

func validGovernedAudience(value string) bool {
	switch value {
	case "foundation", "operator", "client", "workspace", "engineering":
		return true
	default:
		return false
	}
}

func validGovernedInstallMode(value string) bool {
	switch value {
	case "owner-only", "owner-provisions", "self-service":
		return true
	default:
		return false
	}
}

func validGovernedPearlRole(value string) bool {
	switch value {
	case "authority", "proxy", "workflow", "workspace", "template", "test":
		return true
	default:
		return false
	}
}

func validGovernedClientAccess(value string) bool {
	switch value {
	case "none", "scoped-share", "self-owned":
		return true
	default:
		return false
	}
}

func validGovernedAdminSurface(value string) bool {
	switch value {
	case "hidden-authority", "same-pearl", "deployment-only":
		return true
	default:
		return false
	}
}
