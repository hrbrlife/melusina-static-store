package main

// Public leaf versions live beside a single "current" symlink. Opening that
// symlink as a directory once pins both reads to the same version, even when
// a renewal replaces the link between the two file opens.

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	publicLeafPairLayoutRefused = "public-leaf-pair-layout-refused"
	publicLeafPairNoVersion     = "public-leaf-pair-no-complete-version"
	publicLeafPairWriteRefused  = "public-leaf-pair-write-refused"
)

// publicLeafPairRoot recognizes the Store renderer's path contract. Other TLS
// configurations retain their existing ordinary-file behavior; renewal itself
// requires this layout and cannot publish two independently replaced files.
func publicLeafPairRoot(certPath, keyPath string) (string, bool, error) {
	certDir, keyDir := filepath.Dir(certPath), filepath.Dir(keyPath)
	paired := filepath.Base(certDir) == "current" || filepath.Base(keyDir) == "current"
	if !paired {
		return "", false, nil
	}
	if !filepath.IsAbs(certPath) || !filepath.IsAbs(keyPath) || filepath.Clean(certPath) != certPath ||
		filepath.Clean(keyPath) != keyPath || certDir != keyDir || filepath.Base(certDir) != "current" ||
		filepath.Base(certPath) != "cert.pem" || filepath.Base(keyPath) != "key.pem" {
		return "", false, fmt.Errorf("%s: cert and key must be current/cert.pem and current/key.pem in one absolute directory", publicLeafPairLayoutRefused)
	}
	return filepath.Dir(certDir), true, nil
}

func publicLeafVersionName() (string, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return "v-" + time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(nonce[:]), nil
}

func syncPublicLeafDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writePublicLeafVersionFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// publishPublicLeafPair does not change current until both files and their
// containing directory are durable. Previous versions remain available for
// restart recovery; failed/incomplete versions are ignored by that recovery.
func publishPublicLeafPair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	root, paired, err := publicLeafPairRoot(certPath, keyPath)
	if err != nil {
		return err
	}
	if !paired {
		return fmt.Errorf("%s: renewal requires current/cert.pem and current/key.pem", publicLeafPairLayoutRefused)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("%s: %w", servedTLSKeyPairRefused, err)
	}
	versions := filepath.Join(root, "versions")
	if err := os.MkdirAll(versions, 0o700); err != nil {
		return fmt.Errorf("%s: %w", publicLeafPairWriteRefused, err)
	}
	if err := syncPublicLeafDir(root); err != nil {
		return fmt.Errorf("%s: sync root: %w", publicLeafPairWriteRefused, err)
	}
	name, err := publicLeafVersionName()
	if err != nil {
		return fmt.Errorf("%s: version name: %w", publicLeafPairWriteRefused, err)
	}
	version := filepath.Join(versions, name)
	if err := os.Mkdir(version, 0o700); err != nil {
		return fmt.Errorf("%s: create version: %w", publicLeafPairWriteRefused, err)
	}
	// A crash here leaves an incomplete, unlinked version; the old link lives.
	if err := writePublicLeafVersionFile(filepath.Join(version, "key.pem"), keyPEM, 0o600); err != nil {
		return fmt.Errorf("%s: key: %w", publicLeafPairWriteRefused, err)
	}
	if err := writePublicLeafVersionFile(filepath.Join(version, "cert.pem"), certPEM, 0o644); err != nil {
		return fmt.Errorf("%s: cert: %w", publicLeafPairWriteRefused, err)
	}
	if err := syncPublicLeafDir(version); err != nil {
		return fmt.Errorf("%s: sync version: %w", publicLeafPairWriteRefused, err)
	}
	if err := syncPublicLeafDir(versions); err != nil {
		return fmt.Errorf("%s: sync versions: %w", publicLeafPairWriteRefused, err)
	}
	return swapPublicLeafLink(root, name)
}

func swapPublicLeafLink(root, name string) error {
	// A random temporary name also lets a crashed invocation coexist with the
	// next one; only the final rename has any effect on readers.
	tempName, err := publicLeafVersionName()
	if err != nil {
		return fmt.Errorf("%s: link name: %w", publicLeafPairWriteRefused, err)
	}
	temp := filepath.Join(root, ".current-"+tempName)
	if err := os.Symlink(filepath.Join("versions", name), temp); err != nil {
		return fmt.Errorf("%s: make link: %w", publicLeafPairWriteRefused, err)
	}
	if err := os.Rename(temp, filepath.Join(root, "current")); err != nil {
		return fmt.Errorf("%s: swap link: %w", publicLeafPairWriteRefused, err)
	}
	if err := syncPublicLeafDir(root); err != nil {
		return fmt.Errorf("%s: sync link: %w", publicLeafPairWriteRefused, err)
	}
	return nil
}

// readPublicLeafPairFromRoot is kept separate so a test can swap current
// exactly between the reads and prove both come from the opened directory.
func readPublicLeafPairFromRoot(dir *os.Root, betweenReads func()) ([]byte, []byte, error) {
	read := func(name string) ([]byte, error) {
		file, err := dir.Open(name)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return io.ReadAll(file)
	}
	cert, err := read("cert.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("%s: cert: %w", servedTLSReadFailed, err)
	}
	if betweenReads != nil {
		betweenReads()
	}
	key, err := read("key.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("%s: key: %w", servedTLSReadFailed, err)
	}
	return cert, key, nil
}

func readPublishedPublicLeafPair(certPath, keyPath string) ([]byte, []byte, error) {
	return readPublishedPublicLeafPairWithHook(certPath, keyPath, nil)
}

func readPublishedPublicLeafPairWithHook(certPath, keyPath string, betweenReads func()) ([]byte, []byte, error) {
	root, paired, err := publicLeafPairRoot(certPath, keyPath)
	if err != nil {
		return nil, nil, err
	}
	if !paired {
		return nil, nil, fmt.Errorf("%s: not a public leaf pair", publicLeafPairLayoutRefused)
	}
	link := filepath.Join(root, "current")
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return nil, nil, fmt.Errorf("%s: current must be one symlink: %v", publicLeafPairLayoutRefused, err)
	}
	target, err := os.Readlink(link)
	if err != nil || filepath.Clean(target) != target || filepath.Dir(target) != "versions" ||
		!strings.HasPrefix(filepath.Base(target), "v-") {
		return nil, nil, fmt.Errorf("%s: current must target a version directory: %q: %v", publicLeafPairLayoutRefused, target, err)
	}
	dir, err := os.OpenRoot(link)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", servedTLSReadFailed, err)
	}
	defer dir.Close()
	return readPublicLeafPairFromRoot(dir, betweenReads)
}

// recoverPublicLeafPair runs before the Store's first TLS load. It promotes
// the newest complete, matching, currently valid version, including one whose
// writer crashed after syncing the directory but before swapping current.
// Incomplete and mismatched versions cannot become live.
func recoverPublicLeafPair(certPath, keyPath string, now time.Time, logf func(string, ...any)) error {
	root, paired, err := publicLeafPairRoot(certPath, keyPath)
	if err != nil || !paired {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(root, "versions"))
	if err != nil {
		return fmt.Errorf("%s: %w", publicLeafPairNoVersion, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "v-") {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	var lastRefusal error
	for _, name := range names {
		dir, err := os.OpenRoot(filepath.Join(root, "versions", name))
		if err != nil {
			lastRefusal = err
			continue
		}
		cert, key, readErr := readPublicLeafPairFromRoot(dir, nil)
		dir.Close()
		if readErr != nil {
			lastRefusal = readErr
			if logf != nil {
				logf("public leaf pair startup skipped version %s: %v", name, readErr)
			}
			continue
		}
		if _, err := validateServedTLSPair(cert, key, now, nil); err != nil {
			lastRefusal = err
			if logf != nil {
				logf("public leaf pair startup skipped version %s: %v", name, err)
			}
			continue
		}
		wanted := filepath.Join("versions", name)
		current, err := os.Readlink(filepath.Join(root, "current"))
		if err == nil && current == wanted {
			return nil
		}
		return swapPublicLeafLink(root, name)
	}
	return fmt.Errorf("%s: newest candidate refused: %v", publicLeafPairNoVersion, lastRefusal)
}
