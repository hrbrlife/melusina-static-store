// Package spkicon extracts an app's own market icon from the .spk bytes the
// store already holds and hash-verifies.
//
// The icon is NOT a separate publish input. Every pkgdef embeds it in the
// manifest (metadata.icons.market), so the package the publish gate already
// verified against the on-chain ReleaseEntry carries the authoritative icon.
// Reading it here keeps icons out of metadata.json — which is appHash-bound via
// apphash.Canonical(spk, metadata), so putting an icon reference there would
// force a 3-of-4 Squads re-sign of every app to change a presentation asset.
//
// .spk layout (see go-sandstorm exp/spk PackInto, the writer this mirrors):
//
//	MagicNumber (8 bytes)
//	xz stream:
//	  capnp message 1: Signature   (skipped here; the publish gate is the
//	                                trust authority, not this reader)
//	  capnp message 2: Archive     (contains "sandstorm-manifest")
package spkicon

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"capnproto.org/go/capnp/v3"
	"github.com/ulikunitz/xz"
	"zenhack.net/go/sandstorm/capnp/spk"
)

// ErrNoIcon reports that the package parsed cleanly but carries no usable
// market/appGrid icon. Callers treat this as "this app has no icon", never as a
// package-integrity failure — an app is allowed to ship without one.
var ErrNoIcon = errors.New("spkicon: package declares no usable icon")

const (
	// manifestName is the archive entry every .spk carries at its root.
	manifestName = "sandstorm-manifest"

	// maxDecompressed bounds the xz expansion so a malicious or corrupt package
	// cannot exhaust memory here. Real packages run tens of MB; 512 MiB is far
	// above any legitimate app and far below an OOM.
	maxDecompressed = 512 << 20

	// maxIcon bounds a single extracted icon. package.capnp documents 64kB for
	// market and 256kB for marketBig, doubled for dpi2x; 2 MiB leaves headroom
	// without letting a bogus manifest blow up the catalog.
	maxIcon = 2 << 20
)

// Icon is one extracted image plus the file extension it should be served with.
type Icon struct {
	Data []byte
	Ext  string // "svg" or "png", without the dot
}

// Extract reads the market icon out of raw .spk bytes.
//
// Preference order is market -> marketBig -> appGrid: market is the icon the
// pkgdef author sized for exactly this surface (a store grid), and appGrid is
// the documented fallback when market is omitted. Within one icon, svg wins
// over png because it stays sharp at any card size; png prefers dpi2x for the
// same reason.
func Extract(spkBytes []byte) (Icon, error) {
	archive, err := readArchive(spkBytes)
	if err != nil {
		return Icon{}, err
	}
	manifest, err := readManifest(archive)
	if err != nil {
		return Icon{}, err
	}
	if !manifest.HasMetadata() {
		return Icon{}, ErrNoIcon
	}
	metadata, err := manifest.Metadata()
	if err != nil {
		return Icon{}, fmt.Errorf("spkicon: read metadata: %w", err)
	}
	icons := metadata.Icons()

	for _, candidate := range []struct {
		name string
		get  func() (spk.Metadata_Icon, error)
	}{
		{"market", icons.Market},
		{"marketBig", icons.MarketBig},
		{"appGrid", icons.AppGrid},
	} {
		icon, err := candidate.get()
		if err != nil {
			// A single unreadable icon slot must not hide a usable sibling.
			continue
		}
		got, err := decodeIcon(icon)
		if errors.Is(err, ErrNoIcon) {
			continue
		}
		if err != nil {
			return Icon{}, fmt.Errorf("spkicon: %s: %w", candidate.name, err)
		}
		return got, nil
	}
	return Icon{}, ErrNoIcon
}

// decodeIcon resolves one Icon union into servable bytes.
func decodeIcon(icon spk.Metadata_Icon) (Icon, error) {
	switch icon.Which() {
	case spk.Metadata_Icon_Which_svg:
		svg, err := icon.SvgBytes()
		if err != nil {
			return Icon{}, fmt.Errorf("read svg: %w", err)
		}
		if len(svg) == 0 {
			return Icon{}, ErrNoIcon
		}
		if len(svg) > maxIcon {
			return Icon{}, fmt.Errorf("svg icon is %d bytes, cap %d", len(svg), maxIcon)
		}
		return Icon{Data: append([]byte(nil), svg...), Ext: "svg"}, nil

	case spk.Metadata_Icon_Which_png:
		png := icon.Png()
		// dpi2x first: the store grid renders these well above 1x size, so the
		// high-dpi asset is the one that stays crisp.
		for _, get := range []func() ([]byte, error){png.Dpi2x, png.Dpi1x} {
			data, err := get()
			if err != nil {
				continue
			}
			if len(data) == 0 {
				continue
			}
			if len(data) > maxIcon {
				return Icon{}, fmt.Errorf("png icon is %d bytes, cap %d", len(data), maxIcon)
			}
			return Icon{Data: append([]byte(nil), data...), Ext: "png"}, nil
		}
		return Icon{}, ErrNoIcon

	default:
		return Icon{}, ErrNoIcon
	}
}

// readArchive strips the magic header, bounds-decompresses the xz stream, and
// returns the Archive — the second capnp message, after the signature.
func readArchive(spkBytes []byte) (spk.Archive, error) {
	var zero spk.Archive
	if len(spkBytes) < len(spk.MagicNumber) {
		return zero, fmt.Errorf("spkicon: package is %d bytes, shorter than the magic header", len(spkBytes))
	}
	if !bytes.Equal(spkBytes[:len(spk.MagicNumber)], spk.MagicNumber) {
		return zero, errors.New("spkicon: package does not start with the .spk magic number")
	}

	xzReader, err := xz.NewReader(bytes.NewReader(spkBytes[len(spk.MagicNumber):]))
	if err != nil {
		return zero, fmt.Errorf("spkicon: open xz stream: %w", err)
	}
	// LimitReader caps expansion; capnp's decoder streams message-by-message so
	// nothing beyond the archive header and its segments is ever materialized.
	decoder := capnp.NewDecoder(io.LimitReader(xzReader, maxDecompressed))
	// The Archive message inlines every file in the package, so it routinely
	// exceeds capnp's 64 MiB default decode limit — a real app is tens to
	// hundreds of MiB uncompressed. Raise it to the same ceiling the xz
	// LimitReader already enforces, so maxDecompressed stays the single bound.
	decoder.MaxMessageSize = maxDecompressed

	// Message 1 is the signature. The publish gate (VerifyPublish) is the trust
	// authority for it; decoding here only advances the stream.
	if _, err := decoder.Decode(); err != nil {
		return zero, fmt.Errorf("spkicon: decode signature message: %w", err)
	}
	archiveMsg, err := decoder.Decode()
	if err != nil {
		return zero, fmt.Errorf("spkicon: decode archive message: %w", err)
	}
	archive, err := spk.ReadRootArchive(archiveMsg)
	if err != nil {
		return zero, fmt.Errorf("spkicon: read archive root: %w", err)
	}
	return archive, nil
}

// readManifest finds sandstorm-manifest at the archive root and parses it.
func readManifest(archive spk.Archive) (spk.Manifest, error) {
	var zero spk.Manifest
	files, err := archive.Files()
	if err != nil {
		return zero, fmt.Errorf("spkicon: read archive files: %w", err)
	}
	for i := 0; i < files.Len(); i++ {
		file := files.At(i)
		name, err := file.Name()
		if err != nil || name != manifestName {
			continue
		}
		if file.Which() != spk.Archive_File_Which_regular {
			return zero, fmt.Errorf("spkicon: %s is not a regular file", manifestName)
		}
		raw, err := file.Regular()
		if err != nil {
			return zero, fmt.Errorf("spkicon: read %s: %w", manifestName, err)
		}
		manifestMsg, err := capnp.Unmarshal(raw)
		if err != nil {
			return zero, fmt.Errorf("spkicon: unmarshal %s: %w", manifestName, err)
		}
		manifest, err := spk.ReadRootManifest(manifestMsg)
		if err != nil {
			return zero, fmt.Errorf("spkicon: read %s root: %w", manifestName, err)
		}
		return manifest, nil
	}
	return zero, fmt.Errorf("spkicon: archive has no %s", manifestName)
}
