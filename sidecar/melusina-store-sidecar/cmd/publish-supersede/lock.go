package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type appLock struct{ file *os.File }

func acquireAppLock(path string) (*appLock, error) {
	if err := ensureOwnedPrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, err := openFileNoFollow(path, syscall.O_CREAT|syscall.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	st, statOK := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !statOK || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		_ = f.Close()
		return nil, errors.New("per-app lock must be a private regular file")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another publisher holds per-app lock %s", path)
		}
		return nil, err
	}
	return &appLock{file: f}, nil
}

func (l *appLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	return l.file.Close()
}
