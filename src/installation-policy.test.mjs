import test from "node:test";
import assert from "node:assert/strict";
import {
  canSelfInstall,
  installationFor,
  installationPresentation,
  isVisibleInPublicBazaar,
} from "./installation-policy.js";

const workspace = {
  installation: {
    audience: "workspace",
    install_mode: "self-service",
    pearl_role: "workspace",
    client_access: "self-owned",
    admin_surface: "same-pearl",
  },
};

test("only an explicit valid self-service policy enables direct install", () => {
  assert.ok(installationFor(workspace));
  assert.equal(canSelfInstall(workspace), true);
  assert.equal(installationPresentation(workspace).label, "INSTALL");
  assert.equal(canSelfInstall({ installation: { install_mode: "self-service" } }), false);
  assert.equal(canSelfInstall({}), false);
});

test("provisioned and owner-only pearls never expose direct installation", () => {
  const provisioned = {
    installation: {
      audience: "client", install_mode: "owner-provisions", pearl_role: "workspace",
      client_access: "self-owned", admin_surface: "same-pearl",
    },
  };
  const foundation = {
    installation: {
      audience: "foundation", install_mode: "owner-only", pearl_role: "authority",
      client_access: "none", admin_surface: "hidden-authority",
    },
  };
  assert.equal(canSelfInstall(provisioned), false);
  assert.equal(installationPresentation(provisioned).label, "OWNER PROVISIONS");
  assert.equal(canSelfInstall(foundation), false);
  assert.equal(installationPresentation(foundation).label, "OWNER MANAGED");
});

test("normal Bazaar browsing hides internal modes while retaining a safe migration state", () => {
  assert.equal(isVisibleInPublicBazaar(workspace), true);
  assert.equal(isVisibleInPublicBazaar({ installation: {
    audience: "engineering", install_mode: "owner-only", pearl_role: "test",
    client_access: "none", admin_surface: "deployment-only",
  } }), false);
  assert.equal(isVisibleInPublicBazaar({}), true);
  assert.equal(installationPresentation({}).label, "POLICY PENDING");
});
