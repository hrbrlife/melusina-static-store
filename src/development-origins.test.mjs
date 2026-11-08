import { test } from "node:test";
import Assert from "node:assert/strict";
import { developmentOrigins } from "./development-origins.js";

test("local development frontend retains the existing loopback destinations", () => {
  Assert.deepEqual(developmentOrigins(), { shell: "http://local.sandstorm.io:6090",
    packages: "http://local.sandstorm.io:6092" });
});
test("remote development frontend targets exact separate HTTPS services", () => {
  Assert.deepEqual(developmentOrigins("melusina-remote-development-v1"), {
    shell: "https://shell.sailsto.com", packages: "https://store.sailsto.com",
  });
});
test("a URL or unknown profile cannot become a frontend destination", () => {
  for (const value of ["https://unrelated.invalid", "production", "", null, {},
    "melusina-remote-development-v1?url=elsewhere"]) {
    Assert.throws(() => developmentOrigins(value), /unknown-development/);
  }
});
