package installerrelease

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const releasetestImport = "github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"

// TestReleasetestIsImportedOnlyByTests: the fixture package signs entries
// with label-derived keys. No production file of this module may link it.
func TestReleasetestIsImportedOnlyByTests(t *testing.T) {
	root := filepath.Join("..", "..")
	var testImporters int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", ".git", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			if p, _ := strconv.Unquote(spec.Path.Value); p == releasetestImport {
				if !strings.HasSuffix(path, "_test.go") {
					t.Errorf("production file %s imports the test fixture package", path)
				}
				testImporters++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Positive control: the walk does see the tests that use it.
	if testImporters == 0 {
		t.Fatal("no test imports releasetest; the scan walked the wrong tree")
	}
}
