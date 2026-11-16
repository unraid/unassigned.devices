package guardian

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func CaptureSnapshot(cfg Config, device *Device) DiagnosticSnapshot {
	s := DiagnosticSnapshot{
		SchemaVersion: SchemaVersion, CapturedAt: time.Now().UTC(), Files: make(map[string]string),
	}
	s.Hostname, _ = os.Hostname()
	s.Kernel = platformKernelVersion()
	s.Uptime = readTrim(filepath.Join(cfg.ProcRoot, "uptime"))
	global := []string{
		"meminfo", "loadavg", "vmstat", "diskstats", "mdstat", "swaps", "mounts",
		"pressure/cpu", "pressure/io", "pressure/memory", "sys/fs/file-nr", "sys/fs/inode-nr", "sys/kernel/tainted",
	}
	capturePstore(cfg, &s)
	for _, rel := range global {
		path := filepath.Join(cfg.ProcRoot, filepath.FromSlash(rel))
		if b, err := readBounded(path, 256<<10); err == nil {
			s.Files["proc/"+rel] = b
		} else if !errors.Is(err, os.ErrNotExist) {
			s.Errors = append(s.Errors, path+": "+err.Error())
		}
	}
	if b, err := readBounded(filepath.Join(cfg.ProcRoot, "self", "mountinfo"), 512<<10); err == nil {
		s.Files["proc/self/mountinfo"] = b
	} else {
		s.Errors = append(s.Errors, "self mountinfo: "+err.Error())
	}
	for _, path := range cfg.SyslogPaths {
		if tail, err := copyTail(path, cfg.SyslogTailBytes); err == nil {
			s.Files["syslog:"+path] = tail
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			s.Errors = append(s.Errors, path+": "+err.Error())
		}
	}
	s.SHFS = CheckSHFS(cfg)
	relevant := make(map[int]bool)
	if device != nil {
		scan := ScanUsage(cfg, *device, true)
		for _, r := range scan.References {
			if r.PID > 0 {
				relevant[r.PID] = true
			}
		}
		if len(scan.Errors) > 0 {
			s.Files["target_scan_errors"] = strings.Join(scan.Errors, "\n")
		}
		ds := captureDeviceSnapshot(cfg, *device)
		s.Device = &ds
	}
	s.Processes = captureProcesses(cfg, relevant)
	s.Errors = uniqueStrings(s.Errors)
	return s
}

func capturePstore(cfg Config, snapshot *DiagnosticSnapshot) {
	root := filepath.Join(cfg.SysRoot, "fs", "pstore")
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		snapshot.Errors = append(snapshot.Errors, "pstore: "+err.Error())
		return
	}
	const totalLimit = int64(2 << 20)
	var total int64
	for _, entry := range entries {
		if total >= totalLimit || !entry.Type().IsRegular() {
			continue
		}
		remaining := totalLimit - total
		limit := int64(256 << 10)
		if remaining < limit {
			limit = remaining
		}
		value, readErr := readBounded(filepath.Join(root, entry.Name()), limit)
		if readErr != nil {
			snapshot.Errors = append(snapshot.Errors, "pstore/"+entry.Name()+": "+readErr.Error())
			continue
		}
		snapshot.Files["pstore/"+entry.Name()] = value
		total += int64(len(value))
	}
}

func CheckSHFS(cfg Config) SHFSHealth {
	h := SHFSHealth{}
	if mounts, err := selfMounts(cfg); err != nil {
		h.Error = "mountinfo: " + err.Error()
	} else {
		connections := make(map[string]string)
		for _, mount := range mounts {
			fsType, source := strings.ToLower(mount.FSType), strings.ToLower(filepath.Base(mount.Source))
			if fsType != "fuse.shfs" || source != "shfs" {
				continue
			}
			mountPoint := filepath.Clean(mount.MountPoint)
			if _, exists := connections[mount.MajorMinor]; !exists {
				connections[mount.MajorMinor] = mountPoint
			}
			if filepath.Clean(mount.MountPoint) == filepath.Clean(cfg.SHFSPath) {
				h.MountFSType, h.MountSource = mount.FSType, mount.Source
				h.MountVerified = true
			}
		}
		for _, mountPoint := range connections {
			h.MountPoints = append(h.MountPoints, mountPoint)
		}
		sort.Strings(h.MountPoints)
		if !h.MountVerified {
			h.Error = "shfs FUSE mount was not found at " + cfg.SHFSPath
		}
	}
	type probeResult struct{ err error }
	ch := make(chan probeResult, 1)
	go func() {
		dir, err := os.Open(cfg.SHFSPath)
		if err == nil {
			_, readErr := dir.Readdirnames(1)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				err = readErr
			}
			if closeErr := dir.Close(); err == nil {
				err = closeErr
			}
		}
		ch <- probeResult{err: err}
	}()
	select {
	case result := <-ch:
		h.PathAccessible = result.err == nil
		if result.err != nil {
			h.Error = joinHealthError(h.Error, "directory probe: "+result.err.Error())
		}
	case <-time.After(3 * time.Second):
		h.Error = joinHealthError(h.Error, "directory probe timed out")
	}
	dirs, err := os.ReadDir(cfg.ProcRoot)
	if err != nil {
		if h.Error == "" {
			h.Error = err.Error()
		}
		return h
	}
	var shfsPIDs []int
	for _, dir := range dirs {
		pid, err := strconv.Atoi(dir.Name())
		if err != nil || pid <= 0 {
			continue
		}
		comm := readTrim(filepath.Join(cfg.ProcRoot, dir.Name(), "comm"))
		if comm != "shfs" {
			continue
		}
		shfsPIDs = append(shfsPIDs, pid)
	}
	sort.Ints(shfsPIDs)
	h.PIDs = shfsPIDs
	if len(shfsPIDs) == 0 {
		h.Error = joinHealthError(h.Error, "no comm=shfs process was found")
		return h
	}
	if len(h.MountPoints) != len(shfsPIDs) {
		h.Error = joinHealthError(h.Error, fmt.Sprintf("shfs mount/process count mismatch: mounts=%v pids=%v", h.MountPoints, shfsPIDs))
		return h
	}
	h.PID = shfsPIDs[0]
	h.ProcessStates = make(map[string]string, len(shfsPIDs))
	for _, pid := range shfsPIDs {
		status, statusErr := readBounded(filepath.Join(cfg.ProcRoot, strconv.Itoa(pid), "status"), 32<<10)
		if statusErr != nil {
			h.Error = joinHealthError(h.Error, fmt.Sprintf("cannot verify shfs pid=%d status: %v", pid, statusErr))
			continue
		}
		name, state := "", ""
		for _, line := range strings.Split(status, "\n") {
			switch {
			case strings.HasPrefix(line, "Name:"):
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			case strings.HasPrefix(line, "State:"):
				state = strings.TrimSpace(strings.TrimPrefix(line, "State:"))
			}
		}
		h.ProcessStates[strconv.Itoa(pid)] = state
		if pid == h.PID {
			h.ProcessState = state
		}
		if name != "shfs" {
			h.Error = joinHealthError(h.Error, fmt.Sprintf("shfs pid=%d identity mismatch: status name=%q", pid, name))
		}
	}
	return h
}

func joinHealthError(existing, next string) string {
	if existing == "" {
		return next
	}
	if next == "" {
		return existing
	}
	return existing + "; " + next
}

func shfsHealthy(h SHFSHealth) bool {
	pids := shfsPIDSet(h)
	if h.Error != "" || !h.PathAccessible || !h.MountVerified || len(pids) == 0 {
		return false
	}
	for _, pid := range pids {
		state := h.ProcessState
		if len(h.ProcessStates) > 0 {
			state = h.ProcessStates[strconv.Itoa(pid)]
		}
		state = strings.TrimSpace(state)
		if !strings.HasPrefix(state, "S") && !strings.HasPrefix(state, "R") {
			return false
		}
	}
	return true
}

func shfsPIDSet(h SHFSHealth) []int {
	if len(h.PIDs) > 0 {
		pids := append([]int(nil), h.PIDs...)
		sort.Ints(pids)
		return pids
	}
	if h.PID > 0 {
		return []int{h.PID}
	}
	return nil
}

func captureProcesses(cfg Config, relevant map[int]bool) []ProcessSnapshot {
	dirs, err := os.ReadDir(cfg.ProcRoot)
	if err != nil {
		return nil
	}
	important := map[string]bool{"shfs": true, "emhttpd": true, "smbd": true, "nfsd": true, "dockerd": true, "containerd": true, "udevd": true, "systemd-udevd": true}
	var out []ProcessSnapshot
	for _, dir := range dirs {
		pid, err := strconv.Atoi(dir.Name())
		if err != nil {
			continue
		}
		base := filepath.Join(cfg.ProcRoot, dir.Name())
		comm := readTrim(filepath.Join(base, "comm"))
		status, statusErr := readBounded(filepath.Join(base, "status"), 32<<10)
		if statusErr != nil {
			continue
		}
		p := ProcessSnapshot{PID: pid, Comm: comm, Status: status, WChan: readTrim(filepath.Join(base, "wchan"))}
		p.Namespace, _ = readMountNamespace(cfg.ProcRoot, dir.Name())
		if entries, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
			p.FDCount = len(entries)
		}
		if important[comm] || relevant[pid] {
			p.Stack, _ = readBounded(filepath.Join(base, "stack"), 32<<10)
			p.MountInfo, _ = readBounded(filepath.Join(base, "mountinfo"), 256<<10)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

func captureDeviceSnapshot(cfg Config, d Device) DeviceSnapshot {
	ds := DeviceSnapshot{Identity: d, Sysfs: make(map[string]string), Udev: make(map[string]string)}
	for _, b := range d.Blocks {
		base := filepath.Join(cfg.SysRoot, "class", "block", b.Name)
		for _, rel := range []string{"dev", "diskseq", "ro", "size", "stat", "inflight", "uevent", "queue/logical_block_size", "queue/physical_block_size", "queue/write_cache", "device/state", "device/timeout"} {
			if v, err := readBounded(filepath.Join(base, filepath.FromSlash(rel)), 64<<10); err == nil {
				ds.Sysfs[b.Name+"/"+rel] = v
			}
		}
		for _, rel := range []string{"holders", "slaves"} {
			if dirs, err := os.ReadDir(filepath.Join(base, rel)); err == nil {
				var names []string
				for _, x := range dirs {
					names = append(names, x.Name())
				}
				ds.Sysfs[b.Name+"/"+rel] = strings.Join(names, ",")
			}
		}
		udevPath := filepath.Join(cfg.RunRoot, "udev", "data", "b"+b.MajorMinor)
		if v, err := readBounded(udevPath, 256<<10); err == nil {
			ds.Udev[b.Name] = v
		}
	}
	usb := filepath.Join(cfg.SysRoot, filepath.FromSlash(d.USBPath))
	for _, rel := range []string{"uevent", "authorized", "busnum", "devnum", "devpath", "idVendor", "idProduct", "serial", "product", "manufacturer", "power/runtime_status", "power/runtime_active_time", "power/runtime_suspended_time"} {
		if v, err := readBounded(filepath.Join(usb, filepath.FromSlash(rel)), 64<<10); err == nil {
			ds.Sysfs["usb/"+rel] = v
		}
	}
	if fileExists(filepath.Join(usb, "remove")) {
		ds.Sysfs["usb/remove"] = "present"
	}
	return ds
}

func readBounded(path string, max int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return "", err
	}
	if int64(len(b)) > max {
		b = append(b[:max], []byte("\n[truncated]\n")...)
	}
	return string(b), nil
}

func CreateDiagnosticsArchive(cfg Config, logDir, output string) error {
	if output == "" {
		return errors.New("diagnostics output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(output), ".diagnostics-*.zip")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	zw := zip.NewWriter(tmp)
	snapshot := CaptureSnapshot(cfg, nil)
	b, _ := json.MarshalIndent(snapshot, "", "  ")
	if err := addZipBytes(zw, "current/boot-snapshot.json", b); err != nil {
		zw.Close()
		tmp.Close()
		return err
	}
	root := filepath.Clean(logDir)
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		if samePath(path, output) || samePath(path, tmpPath) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if info.Size() > 64<<20 {
			return addZipBytes(zw, filepath.ToSlash(filepath.Join("logs", rel))+".omitted.txt", []byte(fmt.Sprintf("omitted: file is %d bytes", info.Size())))
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: filepath.ToSlash(filepath.Join("logs", rel)), Method: zip.Deflate})
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(w, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		zw.Close()
		tmp.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runtimeGOOSWindows() {
		_ = os.Remove(output)
	}
	if err := os.Rename(tmpPath, output); err != nil {
		return err
	}
	return syncDir(filepath.Dir(output))
}

func addZipBytes(zw *zip.Writer, name string, b []byte) error {
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func samePath(a, b string) bool {
	aa, _ := filepath.Abs(a)
	bb, _ := filepath.Abs(b)
	return strings.EqualFold(aa, bb)
}
