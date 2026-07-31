package spkicon

import (
	"bytes"
	"errors"
	"testing"

	"capnproto.org/go/capnp/v3"
	"github.com/ulikunitz/xz"
	"zenhack.net/go/sandstorm/capnp/spk"
)

// iconSpec describes the icon slots a synthetic package declares.
type iconSpec struct {
	marketSVG    string
	marketPNG1x  []byte
	marketPNG2x  []byte
	appGridSVG   string
	omitMetadata bool
}

// buildSPK assembles a real .spk byte stream — magic, xz, capnp Signature then
// Archive — so the tests exercise the same parser production does rather than a
// stand-in. Mirrors go-sandstorm exp/spk PackInto.
func buildSPK(t *testing.T, spec iconSpec, manifestName string) []byte {
	t.Helper()

	manifestMsg, manifestSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("new manifest message: %v", err)
	}
	manifest, err := spk.NewRootManifest(manifestSeg)
	if err != nil {
		t.Fatalf("new manifest: %v", err)
	}
	if !spec.omitMetadata {
		metadata, err := manifest.NewMetadata()
		if err != nil {
			t.Fatalf("new metadata: %v", err)
		}
		icons := metadata.Icons()
		if spec.marketSVG != "" {
			icon, err := icons.NewMarket()
			if err != nil {
				t.Fatalf("new market icon: %v", err)
			}
			if err := icon.SetSvg(spec.marketSVG); err != nil {
				t.Fatalf("set market svg: %v", err)
			}
		}
		if spec.marketPNG1x != nil || spec.marketPNG2x != nil {
			icon, err := icons.NewMarket()
			if err != nil {
				t.Fatalf("new market icon: %v", err)
			}
			// SetPng selects the union arm; the group setters alone leave the
			// discriminant on "unknown".
			icon.SetPng()
			png := icon.Png()
			if spec.marketPNG1x != nil {
				if err := png.SetDpi1x(spec.marketPNG1x); err != nil {
					t.Fatalf("set dpi1x: %v", err)
				}
			}
			if spec.marketPNG2x != nil {
				if err := png.SetDpi2x(spec.marketPNG2x); err != nil {
					t.Fatalf("set dpi2x: %v", err)
				}
			}
		}
		if spec.appGridSVG != "" {
			icon, err := icons.NewAppGrid()
			if err != nil {
				t.Fatalf("new appGrid icon: %v", err)
			}
			if err := icon.SetSvg(spec.appGridSVG); err != nil {
				t.Fatalf("set appGrid svg: %v", err)
			}
		}
	}
	manifestBytes, err := manifestMsg.Marshal()
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	archiveMsg, archiveSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("new archive message: %v", err)
	}
	archive, err := spk.NewRootArchive(archiveSeg)
	if err != nil {
		t.Fatalf("new archive: %v", err)
	}
	files, err := archive.NewFiles(2)
	if err != nil {
		t.Fatalf("new files: %v", err)
	}
	// A decoy entry ahead of the manifest proves the reader selects by name
	// rather than taking the first archive member.
	decoy := files.At(0)
	if err := decoy.SetName("some-other-file"); err != nil {
		t.Fatalf("set decoy name: %v", err)
	}
	if err := decoy.SetRegular([]byte("not the manifest")); err != nil {
		t.Fatalf("set decoy body: %v", err)
	}
	entry := files.At(1)
	if err := entry.SetName(manifestName); err != nil {
		t.Fatalf("set manifest name: %v", err)
	}
	if err := entry.SetRegular(manifestBytes); err != nil {
		t.Fatalf("set manifest body: %v", err)
	}

	sigMsg, sigSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("new signature message: %v", err)
	}
	if _, err := spk.NewRootSignature(sigSeg); err != nil {
		t.Fatalf("new signature: %v", err)
	}

	var out bytes.Buffer
	out.Write(spk.MagicNumber)
	compressed, err := xz.NewWriter(&out)
	if err != nil {
		t.Fatalf("new xz writer: %v", err)
	}
	encoder := capnp.NewEncoder(compressed)
	if err := encoder.Encode(sigMsg); err != nil {
		t.Fatalf("encode signature: %v", err)
	}
	if err := encoder.Encode(archiveMsg); err != nil {
		t.Fatalf("encode archive: %v", err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatalf("close xz writer: %v", err)
	}
	return out.Bytes()
}

func TestExtractPrefersMarketSVG(t *testing.T) {
	pkg := buildSPK(t, iconSpec{marketSVG: "<svg>market</svg>", appGridSVG: "<svg>grid</svg>"}, manifestName)
	icon, err := Extract(pkg)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if icon.Ext != "svg" {
		t.Fatalf("ext = %q, want svg", icon.Ext)
	}
	if string(icon.Data) != "<svg>market</svg>" {
		t.Fatalf("data = %q, want the market icon, not appGrid", icon.Data)
	}
}

func TestExtractFallsBackToAppGrid(t *testing.T) {
	// package.capnp documents appGrid as the fallback when market is omitted.
	pkg := buildSPK(t, iconSpec{appGridSVG: "<svg>grid</svg>"}, manifestName)
	icon, err := Extract(pkg)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if string(icon.Data) != "<svg>grid</svg>" {
		t.Fatalf("data = %q, want the appGrid icon", icon.Data)
	}
}

func TestExtractPrefersHighDPIPNG(t *testing.T) {
	pkg := buildSPK(t, iconSpec{marketPNG1x: []byte("one-x"), marketPNG2x: []byte("two-x")}, manifestName)
	icon, err := Extract(pkg)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if icon.Ext != "png" {
		t.Fatalf("ext = %q, want png", icon.Ext)
	}
	if string(icon.Data) != "two-x" {
		t.Fatalf("data = %q, want the dpi2x asset", icon.Data)
	}
}

func TestExtractUsesDPI1xWhenOnlyOnePresent(t *testing.T) {
	pkg := buildSPK(t, iconSpec{marketPNG1x: []byte("one-x")}, manifestName)
	icon, err := Extract(pkg)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if string(icon.Data) != "one-x" {
		t.Fatalf("data = %q, want the dpi1x asset", icon.Data)
	}
}

func TestExtractReportsNoIconForIconlessPackage(t *testing.T) {
	// An app is allowed to ship without an icon; that must read as ErrNoIcon and
	// never as a package-integrity failure.
	for name, spec := range map[string]iconSpec{
		"no metadata": {omitMetadata: true},
		"no icons":    {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Extract(buildSPK(t, spec, manifestName)); !errors.Is(err, ErrNoIcon) {
				t.Fatalf("err = %v, want ErrNoIcon", err)
			}
		})
	}
}

func TestExtractRejectsNonPackageBytes(t *testing.T) {
	for name, pkg := range map[string][]byte{
		"empty":      {},
		"short":      []byte("abc"),
		"bad magic":  bytes.Repeat([]byte{0x00}, 64),
		"magic only": spk.MagicNumber,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Extract(pkg); err == nil {
				t.Fatal("Extract accepted bytes that are not a package")
			}
		})
	}
}

func TestExtractRequiresManifestEntry(t *testing.T) {
	pkg := buildSPK(t, iconSpec{marketSVG: "<svg/>"}, "not-the-manifest")
	if _, err := Extract(pkg); err == nil {
		t.Fatal("Extract accepted an archive with no sandstorm-manifest")
	}
}
