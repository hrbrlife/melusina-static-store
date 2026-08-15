#!/usr/bin/env node
// Read a decompressed SPK payload from stdin and project only the signed
// sandstorm-manifest icon metadata. The payload starts immediately after the
// eight-byte SPK magic and XZ compression layer.
//
// This helper deliberately has no Store or release-rail behaviour. The caller
// must verify the complete SPK signature and hash before trusting a projection.
//
// Required environment:
//   MELUSINA_CAPNP_NODE=/path/to/capnp.node
//   MELUSINA_SANDSTORM_SOURCE=/path/to/sandstorm/src
//
// Usage:
//   audit-spk-icon.cjs --report
//   audit-spk-icon.cjs --extract <appGrid|market|grain> <png|svg> [dpi1x|dpi2x]

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function usage() {
  process.stderr.write(
    "usage: audit-spk-icon.cjs --report | --extract <appGrid|market|grain> <png|svg> [dpi1x|dpi2x]\\n"
  );
  process.exit(2);
}

const args = process.argv.slice(2);
let command;
if (args.length === 1 && args[0] === "--report") {
  command = { kind: "report" };
} else if (args.length >= 3 && args[0] === "--extract") {
  const [slot, format, variant] = args.slice(1);
  if (!new Set(["appGrid", "market", "grain"]).has(slot)) usage();
  if (format === "svg" && args.length === 3) {
    command = { kind: "extract", slot, format };
  } else if (format === "png" && args.length === 4 && new Set(["dpi1x", "dpi2x"]).has(variant)) {
    command = { kind: "extract", slot, format, variant };
  } else {
    usage();
  }
} else {
  usage();
}

const bindingPath = process.env.MELUSINA_CAPNP_NODE;
const sandstormSource = process.env.MELUSINA_SANDSTORM_SOURCE;
if (!bindingPath || !sandstormSource) {
  process.stderr.write("check=app_icon_lock_source: MELUSINA_CAPNP_NODE and MELUSINA_SANDSTORM_SOURCE are required\\n");
  process.exit(2);
}

const capnp = require(bindingPath);
const schemaRoot = __dirname;
const projection = capnp.import(path.join(schemaRoot, "appgrid-audit.capnp"), path.join(schemaRoot, "appgrid-audit.capnp"), [schemaRoot]);
const sandstorm = capnp.import(
  path.join(sandstormSource, "sandstorm", "package.capnp"),
  path.join(sandstormSource, "sandstorm", "package.capnp"),
  [sandstormSource]
);

function toJs(schema, bytes, options) {
  return capnp.toJs(capnp.fromBytes(bytes, schema, options || {}), function Capability() {});
}

function pngFacts(bytes) {
  const png = Buffer.from(bytes || []);
  const signature = "89504e470d0a1a0a";
  const validSignature = png.length >= 8 && png.subarray(0, 8).toString("hex") === signature;
  const validIHDR = validSignature && png.length >= 33 && png.subarray(12, 16).toString("ascii") === "IHDR" &&
    png.readUInt32BE(8) === 13;
  return {
    bytes: png.length,
    sha256: crypto.createHash("sha256").update(png).digest("hex"),
    pngSignature: validSignature,
    ihdr: validIHDR ? {
      width: png.readUInt32BE(16),
      height: png.readUInt32BE(20),
      bitDepth: png[24],
      colorType: png[25],
    } : null,
  };
}

function iconReport(icon) {
  if (icon && icon.png) {
    return {
      kind: "png",
      dpi1x: pngFacts(icon.png.dpi1x),
      dpi2x: pngFacts(icon.png.dpi2x),
    };
  }
  if (icon && typeof icon.svg === "string") {
    const svg = Buffer.from(icon.svg, "utf8");
    return {
      kind: "svg",
      bytes: svg.length,
      sha256: crypto.createHash("sha256").update(svg).digest("hex"),
    };
  }
  return { kind: "absent" };
}

const raw = fs.readFileSync(0);
const signatureBytes = capnp.expectedSizeFromPrefix(raw);
if (!Number.isSafeInteger(signatureBytes) || signatureBytes <= 0 || signatureBytes >= raw.length) {
  throw new Error("check=app_icon_lock_source: invalid SPK signature-message prefix");
}

const archive = toJs(projection.ArchiveProjection, raw.subarray(signatureBytes));
const manifestFile = (archive.files || []).find((file) => file.name === "sandstorm-manifest");
if (!manifestFile || !manifestFile.regular) {
  throw new Error("check=app_icon_lock_source: sandstorm-manifest missing or non-regular");
}
const manifest = toJs(sandstorm.Manifest, Buffer.from(manifestFile.regular));
const icons = (manifest.metadata && manifest.metadata.icons) || {};

if (command.kind === "report") {
  process.stdout.write(`${JSON.stringify({
    appId: manifest.appId || null,
    appVersion: manifest.appVersion,
    marketingVersion: manifest.appMarketingVersion && manifest.appMarketingVersion.defaultText || null,
    appGrid: iconReport(icons.appGrid),
    market: iconReport(icons.market),
    grain: iconReport(icons.grain),
  })}\n`);
  process.exit(0);
}

const selected = icons[command.slot];
if (command.format === "svg") {
  if (!selected || typeof selected.svg !== "string") {
    throw new Error(`check=app_icon_lock_source: ${command.slot} SVG is absent`);
  }
  process.stdout.write(selected.svg);
} else {
  const png = selected && selected.png && selected.png[command.variant];
  if (!png) {
    throw new Error(`check=app_icon_lock_source: ${command.slot} ${command.variant} PNG is absent`);
  }
  process.stdout.write(Buffer.from(png));
}
