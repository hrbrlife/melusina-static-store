import { test } from "node:test";
import Assert from "node:assert/strict";
import { canStoreInstall, canSelfInstall, isVisibleInPublicBazaar,
  installationPresentation } from "./installation-policy.js";

test("development Bazaar exposes operator and unclassified apps through actual install policy", () => {
  for (const audience of ["foundation", "operator", "engineering", "client", "workspace"]) {
    const app = { installation: { audience, install_mode: "owner-only",
      pearl_role: "authority", client_access: "none", admin_surface: "hidden-authority" } };
    Assert.equal(isVisibleInPublicBazaar(app), true);
    Assert.equal(canSelfInstall(app), true);
    Assert.equal(canStoreInstall(app), true);
    Assert.equal(installationPresentation(app).label, "INSTALL");
  }
  Assert.equal(canStoreInstall({}), true);
});
