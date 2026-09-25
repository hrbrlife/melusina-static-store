'use strict';
// node-module-confinement.cjs -- preloaded (`node --require`) by both release
// providers wherever Node runs a Squads helper or the Squads vault executor.
//
// scripts/release-inputs.py checks the bytes of the script, of what it loads
// beside it and of the node_modules tree it resolves. Node's CommonJS loader
// does not stop there: a module the pinned tree lacks (an optional one such as
// node-fetch's `encoding` or debug's `supports-color`) is looked up in every
// ancestor node_modules, in NODE_PATH, in the node_modules and node_libraries
// folders of the caller's home, and in the global folders the Node build names --
// /usr/share/nodejs on a Debian node, which holds both of those modules -- and
// the pinned executor adds its own fallback search of sibling trees when a
// module does not resolve. Each is code from outside the pinned inputs.
//
// This preload admits exactly: Node's builtins, the main script, and files
// under the roots named in MEL_RELEASE_NODE_MODULE_ROOTS (a JSON array of
// absolute paths, printed by `scripts/release-inputs.py node-roots`). Any other
// resolution is refused with code MODULE_NOT_FOUND, so an optional module
// behaves as absent and a required one fails by name. Paths are compared after
// realpath, so a symlink inside a root that leads out of it is refused too.
// The providers also clear NODE_OPTIONS and NODE_PATH, so nothing is preloaded
// before this file.

const Module = require('module');
const fs = require('fs');
const path = require('path');

const VARIABLE = 'MEL_RELEASE_NODE_MODULE_ROOTS';

function refuseToStart(detail) {
  throw new Error(`node-module-confinement: ${detail}`);
}

let declared;
try {
  declared = JSON.parse(process.env[VARIABLE] || '');
} catch (_) {
  refuseToStart(`${VARIABLE} must be a JSON array of absolute paths`);
}
if (!Array.isArray(declared) || declared.length === 0 ||
    declared.some((entry) => typeof entry !== 'string' || !path.isAbsolute(entry))) {
  refuseToStart(`${VARIABLE} must be a non-empty JSON array of absolute paths`);
}
const main = process.argv[1];
if (typeof main !== 'string' || !path.isAbsolute(main)) {
  refuseToStart('the main script must be named by an absolute path');
}

function real(entry) {
  try {
    return fs.realpathSync(entry);
  } catch (error) {
    return refuseToStart(`${entry} is not usable: ${error.message}`);
  }
}
const roots = declared.map(real);
const mainFile = real(main);

function admitted(file) {
  let resolved;
  try {
    resolved = fs.realpathSync(file);
  } catch (_) {
    return false;
  }
  if (resolved === mainFile) return true;
  return roots.some((root) => resolved === root || resolved.startsWith(root + path.sep));
}

const isBuiltin = typeof Module.isBuiltin === 'function'
  ? Module.isBuiltin
  : (request) => Module.builtinModules.includes(String(request).replace(/^node:/, ''));

const resolveFilename = Module._resolveFilename;
Module._resolveFilename = function confinedResolveFilename(request, parent, isMain, options) {
  const resolved = resolveFilename.call(this, request, parent, isMain, options);
  if (isBuiltin(resolved) || admitted(resolved)) return resolved;
  const error = new Error(
    `node-module-confinement: ${request} resolves to ${resolved}, outside the pinned module roots; refused`);
  error.code = 'MODULE_NOT_FOUND';
  throw error;
};
