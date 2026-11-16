//go:build !linux

package guardian

import (
	"errors"
	"io"
	"os"
	"runtime"
)

type otherLock struct {
	file *os.File
	path string
}

func (l *otherLock) Close() error {
	err := l.file.Close()
	removeErr := os.Remove(l.path)
	if err != nil {
		return err
	}
	return removeErr
}

func platformUnmount(string) error { return errors.New("unmount is supported only on Linux") }
func platformOpenExclusive([]string) ([]ExclusiveHandle, error) {
	return nil, errors.New("exclusive block-device open is supported only on Linux")
}
func platformWriteUSBRemove(string) error { return errors.New("USB remove is supported only on Linux") }
func platformStartUEventMonitor(func(map[string]string)) (func(), error) {
	return func() {}, errors.New("uevent monitoring is supported only on Linux")
}
func platformKernelVersion() string { return runtime.GOOS + "/" + runtime.GOARCH }
func runtimeGOOSWindows() bool      { return runtime.GOOS == "windows" }
func platformAcquireLock(path string) (io.Closer, bool, error) {
	owner := path + ".owner"
	f, err := os.OpenFile(owner, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if errors.Is(err, os.ErrExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &otherLock{file: f, path: owner}, true, nil
}
