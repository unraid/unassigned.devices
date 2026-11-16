package guardian

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ExclusiveHandle interface {
	io.Closer
	Name() string
	MajorMinor() (string, error)
	Sync() error
	SCSISync() error
	SCSIStop() error
}

func acquireTransactionLock(logDir string) (io.Closer, bool, error) {
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return nil, false, err
	}
	return platformAcquireLock(filepath.Join(logDir, ".transaction.lock"))
}

type SystemOps interface {
	Unmount(string) error
	OpenExclusive([]string) ([]ExclusiveHandle, error)
	WriteUSBRemove(string) error
	StartUEventMonitor(func(map[string]string)) (func(), error)
}

type DefaultSystemOps struct{}

func (DefaultSystemOps) Unmount(path string) error { return platformUnmount(path) }
func (DefaultSystemOps) OpenExclusive(paths []string) ([]ExclusiveHandle, error) {
	return platformOpenExclusive(paths)
}
func (DefaultSystemOps) WriteUSBRemove(path string) error { return platformWriteUSBRemove(path) }
func (DefaultSystemOps) StartUEventMonitor(cb func(map[string]string)) (func(), error) {
	return platformStartUEventMonitor(cb)
}

func waitForRemoval(cfg Config, d Device, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var remaining []string
		if fileExists(filepath.Join(cfg.SysRoot, filepath.FromSlash(d.USBPath))) {
			remaining = append(remaining, "usb:"+d.USBPath)
		}
		for _, b := range d.Blocks {
			if fileExists(filepath.Join(cfg.SysRoot, "class", "block", b.Name)) {
				remaining = append(remaining, "sysfs:"+b.Name)
			}
			if fileExists(b.DevNode) {
				remaining = append(remaining, "dev:"+b.DevNode)
			}
			if fileExists(filepath.Join(cfg.RunRoot, "udev", "data", "b"+b.MajorMinor)) {
				remaining = append(remaining, "udev:"+b.MajorMinor)
			}
			remaining = append(remaining, byIDReferences(cfg.DevRoot, b.Name)...)
		}
		if len(remaining) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("device removal did not settle; remaining nodes: %s", strings.Join(uniqueStrings(remaining), ", "))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func byIDReferences(devRoot, kernelName string) []string {
	var out []string
	dirs, _ := filepath.Glob(filepath.Join(devRoot, "disk", "by-*"))
	for _, dir := range dirs {
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			target, err := os.Readlink(path)
			if err == nil && filepath.Base(target) == kernelName {
				out = append(out, "link:"+path)
			}
		}
	}
	return out
}

func closeHandles(handles []ExclusiveHandle) error {
	var errs []error
	for i := len(handles) - 1; i >= 0; i-- {
		if err := handles[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
