// Store-governed installation policy. The live catalog carries this object;
// app metadata and UI defaults may never turn a non-self-service pearl into a
// direct-install target.

const AUDIENCES = new Set(["foundation", "operator", "client", "workspace", "engineering"]);
const INSTALL_MODES = new Set(["owner-only", "owner-provisions", "self-service"]);
const PEARL_ROLES = new Set(["authority", "proxy", "workflow", "workspace", "template", "test"]);
const CLIENT_ACCESS = new Set(["none", "scoped-share", "self-owned"]);
const ADMIN_SURFACES = new Set(["hidden-authority", "same-pearl", "deployment-only"]);

export function installationFor(app) {
  const policy = app?.installation;
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) return null;
  if (!AUDIENCES.has(policy.audience) ||
      !INSTALL_MODES.has(policy.install_mode) ||
      !PEARL_ROLES.has(policy.pearl_role) ||
      !CLIENT_ACCESS.has(policy.client_access) ||
      !ADMIN_SURFACES.has(policy.admin_surface)) return null;
  return policy;
}

// The signed Store UI owns the default-Bazaar policy asset.  Never retain an
// app-supplied installation object when applying it: metadata may describe an
// app but cannot make it directly installable or expose an internal pearl.
export function applyGovernedInstallationPolicy(app, policies) {
  const projected = { ...(app || {}) };
  delete projected.installation;
  const appId = typeof projected.appId === "string" ? projected.appId : "";
  const candidate = policies && typeof policies === "object" && !Array.isArray(policies)
    ? policies[appId]
    : null;
  const policy = installationFor({ installation: candidate });
  if (policy) projected.installation = { ...policy };
  return projected;
}

export function canSelfInstall(app) {
  return installationFor(app)?.install_mode === "self-service";
}

// No foundation, operator, or engineering pearl appears in a normal Bazaar
// browse surface. A missing policy remains visible during a catalog migration,
// but cannot install; that fails closed without making an in-progress catalog
// look silently empty.
export function isVisibleInPublicBazaar(app) {
  const policy = installationFor(app);
  return policy === null || policy.audience === "client" || policy.audience === "workspace";
}

export function installationPresentation(app) {
  const policy = installationFor(app);
  if (!policy) {
    return {
      label: "POLICY PENDING",
      detail: "This catalog entry has no valid installation policy yet; direct installation is disabled.",
    };
  }
  if (policy.install_mode === "self-service") {
    return { label: "INSTALL", detail: "Install this workspace into your governed Melusina Shell tenant." };
  }
  if (policy.install_mode === "owner-provisions") {
    return policy.client_access === "self-owned"
      ? { label: "OWNER PROVISIONS", detail: "Your owner creates the workspace; your organization takes governed ownership after setup." }
      : { label: "OWNER PROVISIONS", detail: "Your owner creates this pearl and grants the appropriate scoped access." };
  }
  return { label: "OWNER MANAGED", detail: "This foundation or internal pearl is deployed and operated by the owner, not installed from Bazaar." };
}
