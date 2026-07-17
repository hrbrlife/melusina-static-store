//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const cgroup2SuperMagic = 0x63677270

// operationContainment owns one cgroup-v2 subtree for exactly one adapter
// command. The production implementation has no process-group-only fallback:
// every descendant must be born inside an atomically selected cgroup so setsid
// and double-fork cannot escape timeout cleanup.
type operationContainment interface {
	Configure(*exec.Cmd)
	Terminate() error
	Cleanup() error
}

var newOperationContainment = newCgroupOperationContainment

type cgroupOperationContainment struct {
	path string
	dir  *os.File
}

func newCgroupOperationContainment(root string) (operationContainment, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("adapter cgroup root must be an absolute clean path")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("adapter cgroup root is unavailable or unsafe: %w", err)
	}
	path, err := os.MkdirTemp(root, "publish-op-")
	if err != nil {
		return nil, fmt.Errorf("create delegated operation cgroup: %w", err)
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &stat); err != nil || uint64(stat.Type) != cgroup2SuperMagic {
		_ = dir.Close()
		return nil, errors.New("adapter containment is not a cgroup-v2 filesystem")
	}
	killFD, err := syscall.Open(filepath.Join(path, "cgroup.kill"), syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("delegated cgroup lacks writable cgroup.kill: %w", err)
	}
	_ = syscall.Close(killFD)
	remove = false
	return &cgroupOperationContainment{path: path, dir: dir}, nil
}

func (c *cgroupOperationContainment) Configure(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, UseCgroupFD: true, CgroupFD: int(c.dir.Fd())}
}

func (c *cgroupOperationContainment) populated() (bool, error) {
	f, err := openRegularFileNoFollow(filepath.Join(c.path, "cgroup.events"))
	if err != nil {
		return false, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return false, errors.New("invalid cgroup.events")
	}
	found := false
	value := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return false, errors.New("malformed cgroup.events")
		}
		if fields[0] != "populated" {
			continue
		}
		if found || (fields[1] != "0" && fields[1] != "1") {
			return false, errors.New("malformed cgroup.events populated field")
		}
		found = true
		value = fields[1] == "1"
	}
	if !found {
		return false, errors.New("cgroup.events omits populated")
	}
	return value, nil
}

func (c *cgroupOperationContainment) killAll() error {
	fd, err := syscall.Open(filepath.Join(c.path, "cgroup.kill"), syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(c.path, "cgroup.kill"))
	_, writeErr := f.WriteString("1\n")
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func (c *cgroupOperationContainment) waitEmpty() error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		populated, err := c.populated()
		if err != nil {
			return err
		}
		if !populated {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("operation cgroup remained populated after kill")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *cgroupOperationContainment) Terminate() error {
	populated, err := c.populated()
	if err != nil {
		return err
	}
	if populated {
		if err := c.killAll(); err != nil {
			return err
		}
	}
	return c.waitEmpty()
}

func (c *cgroupOperationContainment) Cleanup() error {
	if c == nil || c.dir == nil {
		return nil
	}
	terminateErr := c.Terminate()
	closeErr := c.dir.Close()
	c.dir = nil
	removeErr := os.Remove(c.path)
	if terminateErr != nil {
		return terminateErr
	}
	if closeErr != nil {
		return closeErr
	}
	if removeErr != nil {
		return fmt.Errorf("remove operation cgroup %s: %w", strconv.Quote(c.path), removeErr)
	}
	return nil
}
