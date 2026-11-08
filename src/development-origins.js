// Build-time choice for the separate development frontend only.
export function developmentOrigins(profile = "melusina-local-development-v1") {
  if (profile === "melusina-local-development-v1") return Object.freeze({
    shell: "http://local.sandstorm.io:6090", packages: "http://local.sandstorm.io:6092",
  });
  if (profile === "melusina-remote-development-v1") return Object.freeze({
    shell: "https://shell.sailsto.com", packages: "https://store.sailsto.com",
  });
  throw new Error("unknown-development-frontend-profile");
}
