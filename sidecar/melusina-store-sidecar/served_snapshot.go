package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"
)

// A gated serve path (a /packages/ SPK, a /releases/<class>/<name> artifact)
// hashes one private snapshot of the artifact and serves that same snapshot.
//
// It used to hash the published file and then serve a second read of the same
// inode. Anyone able to rewrite that file in place between the two reads got
// their bytes served under X-Store-Gate: verified with the approved hash in
// the response headers (blocker verification 2, 2026-09-24: 1830 of 20000
// requests). The published file is not immutable just because the catalog
// treats it so, so the gate never trusts a second read of it.

// privateServedSnapshot copies exactly size bytes of src into a private file
// and returns that file positioned at offset 0. The caller hashes it, gates
// on that hash and serves it; it never reads src again.
//
// The copy is unreachable from outside this process: it is created 0600 in a
// fresh 0700 directory, and both names are removed before the first byte is
// copied, so only this descriptor refers to it. Under the Store unit
// (PrivateTmp=yes) the directory is also in the service's own /tmp namespace.
// A source that is shorter than size fails the copy; bytes appended after the
// snapshot began are not part of it, and a concurrent in-place rewrite can at
// worst produce a snapshot whose hash the gate then refuses.
func privateServedSnapshot(src io.Reader, size int64) (*os.File, error) {
	if size < 0 {
		return nil, fmt.Errorf("served-snapshot: negative size %d", size)
	}
	dir, err := os.MkdirTemp("", "melusina-store-served-")
	if err != nil {
		return nil, fmt.Errorf("served-snapshot: private directory: %w", err)
	}
	f, err := os.CreateTemp(dir, "artifact-")
	if err != nil {
		_ = os.Remove(dir)
		return nil, fmt.Errorf("served-snapshot: private file: %w", err)
	}
	if err := errors.Join(os.Remove(f.Name()), os.Remove(dir)); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("served-snapshot: unlink private copy: %w", err)
	}
	n, err := io.CopyN(f, src, size)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("served-snapshot: copied %d of %d bytes: %w", n, size, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("served-snapshot: rewind: %w", err)
	}
	return f, nil
}

// refuseGatedArtifactOpen answers a gated artifact that could not be opened as
// a regular file without following a final symlink. A missing path is the
// canonical 404. Anything else (a symlink, a directory, a device or FIFO, an
// unreadable file) is refused by name. Neither case is handed to the static
// file server: that server follows symlinks and applies no gate, so a file
// appearing between this refusal and its own open would be served unverified.
func refuseGatedArtifactOpen(w http.ResponseWriter, r *http.Request, gate string, err error) {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		http.NotFound(w, r)
		return
	}
	http.Error(w, gate+" refused: check=served_artifact: not a regular file opened without following links: "+err.Error(), http.StatusForbidden)
}
