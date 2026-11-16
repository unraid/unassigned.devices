//go:build linux

package guardian

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	sgIO                 = 0x2285
	sgDxferNone          = -1
	netlinkKobjectUEvent = 15
)

type linuxBlockHandle struct {
	fd   int
	name string
}

func (h *linuxBlockHandle) Name() string { return h.name }
func (h *linuxBlockHandle) MajorMinor() (string, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(h.fd, &st); err != nil {
		return "", err
	}
	dev := uint64(st.Rdev)
	major := ((dev & 0x00000000000fff00) >> 8) | ((dev & 0xfffff00000000000) >> 32)
	minor := (dev & 0x00000000000000ff) | ((dev & 0x00000ffffff00000) >> 12)
	return fmt.Sprintf("%d:%d", major, minor), nil
}
func (h *linuxBlockHandle) Close() error {
	if h.fd < 0 {
		return nil
	}
	err := syscall.Close(h.fd)
	h.fd = -1
	return err
}
func (h *linuxBlockHandle) Sync() error { return syscall.Fsync(h.fd) }
func (h *linuxBlockHandle) SCSISync() error {
	return h.sgCommand([]byte{0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 30*time.Second)
}
func (h *linuxBlockHandle) SCSIStop() error {
	return h.sgCommand([]byte{0x1b, 0, 0, 0, 0, 0}, 30*time.Second)
}

type sgIOHeader struct {
	InterfaceID        int32
	Direction          int32
	CommandLength      uint8
	MaxSenseLength     uint8
	IOVecCount         uint16
	TransferLength     uint32
	TransferPointer    uintptr
	CommandPointer     uintptr
	SensePointer       uintptr
	Timeout            uint32
	Flags              uint32
	PackID             int32
	UserPointer        uintptr
	Status             uint8
	MaskedStatus       uint8
	MessageStatus      uint8
	SenseLengthWritten uint8
	HostStatus         uint16
	DriverStatus       uint16
	Residual           int32
	Duration           uint32
	Info               uint32
}

func (h *linuxBlockHandle) sgCommand(command []byte, timeout time.Duration) error {
	if len(command) == 0 || len(command) > 255 {
		return errors.New("invalid SCSI command")
	}
	sense := make([]byte, 64)
	header := sgIOHeader{InterfaceID: 'S', Direction: sgDxferNone, CommandLength: uint8(len(command)), MaxSenseLength: uint8(len(sense)), CommandPointer: uintptr(unsafe.Pointer(&command[0])), SensePointer: uintptr(unsafe.Pointer(&sense[0])), Timeout: uint32(timeout.Milliseconds())}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(h.fd), uintptr(sgIO), uintptr(unsafe.Pointer(&header)))
	if errno != 0 {
		return errno
	}
	if header.Status != 0 || header.HostStatus != 0 || header.DriverStatus != 0 {
		senseLength := int(header.SenseLengthWritten)
		if senseLength > len(sense) {
			senseLength = len(sense)
		}
		return fmt.Errorf("SG_IO failed: status=%#x host=%#x driver=%#x sense=%x", header.Status, header.HostStatus, header.DriverStatus, sense[:senseLength])
	}
	return nil
}

func platformUnmount(path string) error { return syscall.Unmount(path, 0) }

func platformOpenExclusive(paths []string) ([]ExclusiveHandle, error) {
	var out []ExclusiveHandle
	for _, path := range paths {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
		if err != nil {
			_ = closeHandles(out)
			return nil, fmt.Errorf("exclusive open %s: %w", path, err)
		}
		out = append(out, &linuxBlockHandle{fd: fd, name: path})
	}
	return out, nil
}

func platformWriteUSBRemove(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString("1\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func platformStartUEventMonitor(callback func(map[string]string)) (func(), error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, netlinkKobjectUEvent)
	if err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	tv := syscall.NsecToTimeval((500 * time.Millisecond).Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	done := make(chan struct{})
	stopped := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(stopped)
		buf := make([]byte, 64<<10)
		for {
			n, _, recvErr := syscall.Recvfrom(fd, buf, 0)
			if recvErr != nil {
				if recvErr == syscall.EAGAIN || recvErr == syscall.EWOULDBLOCK || recvErr == syscall.EINTR {
					select {
					case <-done:
						return
					default:
						continue
					}
				}
				return
			}
			if n <= 0 {
				continue
			}
			fields := strings.Split(string(buf[:n]), "\x00")
			event := make(map[string]string)
			for i, field := range fields {
				if i == 0 && !strings.Contains(field, "=") {
					event["HEADER"] = field
					continue
				}
				if k, v, ok := strings.Cut(field, "="); ok {
					event[k] = v
				}
			}
			callback(event)
		}
	}()
	return func() {
		once.Do(func() { close(done); _ = syscall.Close(fd) })
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
		}
	}, nil
}

func platformKernelVersion() string {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func platformAcquireLock(path string) (io.Closer, bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return nil, false, nil
		}
		return nil, false, err
	}
	return f, true, nil
}

func runtimeGOOSWindows() bool { return false }
