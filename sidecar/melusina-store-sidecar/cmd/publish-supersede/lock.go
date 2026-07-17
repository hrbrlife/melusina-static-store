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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
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
