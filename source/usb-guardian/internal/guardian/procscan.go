package guardian

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func ScanUsage(cfg Config, d Device, allowSelfMounts bool) ScanResult {
	result := ScanResult{}
	targetMM := make(map[string]bool)
	var targetPaths []string
	var mountpoints []string
	for _, b := range d.Blocks {
		targetMM[b.MajorMinor] = true
		targetPaths = append(targetPaths, b.DevNode)
		for _, m := range b.Mounts {
			mountpoints = append(mountpoints, m.MountPoint)
		}
	}
	usbRoot := filepath.Join(cfg.SysRoot, filepath.FromSlash(d.USBPath))
	if bus, dev := parseInt(readTrim(filepath.Join(usbRoot, "busnum"))), parseInt(readTrim(filepath.Join(usbRoot, "devnum"))); bus > 0 && dev > 0 {
		targetPaths = append(targetPaths, filepath.Join(cfg.DevRoot, "bus", "usb", fmt.Sprintf("%03d", bus), fmt.Sprintf("%03d", dev)))
	}
	if live, err := targetMounts(cfg, d.Blocks); err == nil {
		for _, m := range live {
			mountpoints = append(mountpoints, m.MountPoint)
		}
	} else {
		result.Errors = append(result.Errors, "self mountinfo: "+err.Error())
	}
	mountpoints = uniqueStrings(mountpoints)
	selfNS, err := readMountNamespace(cfg.ProcRoot, "self")
	if err != nil {
		result.Errors = append(result.Errors, "self mount namespace: "+err.Error())
	}
	procDirs, err := os.ReadDir(cfg.ProcRoot)
	if err != nil {
		result.Errors = append(result.Errors, "read proc: "+err.Error())
		return result
	}
	for _, dir := range procDirs {
		pid, err := strconv.Atoi(dir.Name())
		if err != nil || pid <= 0 {
			continue
		}
		procPath := filepath.Join(cfg.ProcRoot, dir.Name())
		name := processName(procPath)
		ns, nsErr := readMountNamespace(cfg.ProcRoot, dir.Name())
		if nsErr != nil && !errors.Is(nsErr, os.ErrNotExist) {
			result.Errors = append(result.Errors, fmt.Sprintf("pid %d mount namespace: %v", pid, nsErr))
		}
		mountData, mountErr := os.ReadFile(filepath.Join(procPath, "mountinfo"))
		if mountErr != nil {
			if !errors.Is(mountErr, os.ErrNotExist) {
				result.Errors = append(result.Errors, fmt.Sprintf("pid %d mountinfo: %v", pid, mountErr))
			}
		} else if mounts, parseErr := ParseMountInfo(string(mountData), pid, ns); parseErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("pid %d mountinfo parse: %v", pid, parseErr))
		} else {
			for _, m := range mounts {
				if !targetMM[m.MajorMinor] && !mountSourceMatches(m.Source, d.Blocks) {
					continue
				}
				if allowSelfMounts && ns != "" && ns == selfNS {
					continue
				}
				result.References = append(result.References, Reference{PID: pid, Process: name, Kind: "mount_namespace", Path: m.MountPoint, Detail: m.MajorMinor, Namespace: ns})
			}
		}
		for _, kind := range []string{"cwd", "root", "exe"} {
			link, linkErr := os.Readlink(filepath.Join(procPath, kind))
			if linkErr == nil && matchesTargetPath(link, targetPaths, mountpoints) {
				result.References = append(result.References, Reference{PID: pid, Process: name, Kind: kind, Path: link, Namespace: ns})
			} else if linkErr != nil && !errors.Is(linkErr, os.ErrNotExist) && !errors.Is(linkErr, os.ErrPermission) {
				result.Errors = append(result.Errors, fmt.Sprintf("pid %d %s: %v", pid, kind, linkErr))
			} else if errors.Is(linkErr, os.ErrPermission) {
				result.Errors = append(result.Errors, fmt.Sprintf("pid %d %s: permission denied", pid, kind))
			}
		}
		fixtureLinks := filepath.Clean(cfg.ProcRoot) != filepath.Clean("/proc")
		scanLinkDir(procPath, "fd", pid, name, ns, targetPaths, mountpoints, fixtureLinks, &result)
		scanLinkDir(procPath, "map_files", pid, name, ns, targetPaths, mountpoints, fixtureLinks, &result)
	}
	scanSwap(cfg, targetPaths, mountpoints, &result)
	scanHoldersAndLoops(cfg, d, mountpoints, &result)
	sort.Slice(result.References, func(i, j int) bool {
		if result.References[i].PID != result.References[j].PID {
			return result.References[i].PID < result.References[j].PID
		}
		if result.References[i].Kind != result.References[j].Kind {
			return result.References[i].Kind < result.References[j].Kind
		}
		return result.References[i].Path < result.References[j].Path
	})
	result.Errors = uniqueStrings(result.Errors)
	return result
}

func scanLinkDir(procPath, sub string, pid int, name, ns string, targets, mountpoints []string, fixtureLinks bool, result *ScanResult) {
	path := filepath.Join(procPath, sub)
	entries, err := os.ReadDir(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			result.Errors = append(result.Errors, fmt.Sprintf("pid %d %s: %v", pid, sub, err))
		}
		return
	}
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(path, entry.Name()))
		if err != nil && fixtureLinks && entry.Type().IsRegular() {
			link = readTrim(filepath.Join(path, entry.Name()))
			err = nil
		}
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
				result.Errors = append(result.Errors, fmt.Sprintf("pid %d %s/%s: %v", pid, sub, entry.Name(), err))
			} else if errors.Is(err, os.ErrPermission) {
				result.Errors = append(result.Errors, fmt.Sprintf("pid %d %s/%s: permission denied", pid, sub, entry.Name()))
			}
			continue
		}
		if matchesTargetPath(link, targets, mountpoints) {
			result.References = append(result.References, Reference{PID: pid, Process: name, Kind: sub, Path: link, Detail: entry.Name(), Namespace: ns})
		}
	}
}

func scanSwap(cfg Config, targetPaths, mountpoints []string, result *ScanResult) {
	f, err := os.Open(filepath.Join(cfg.ProcRoot, "swaps"))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		result.Errors = append(result.Errors, "swaps: "+err.Error())
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	first := true
	for s.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(s.Text())
		if len(fields) == 0 {
			continue
		}
		fields[0] = unescapeMount(fields[0])
		for _, target := range targetPaths {
			if fields[0] == target {
				result.References = append(result.References, Reference{Kind: "swap", Path: fields[0]})
			}
		}
		for _, mountpoint := range mountpoints {
			if pathWithin(fields[0], mountpoint) {
				result.References = append(result.References, Reference{Kind: "swap", Path: fields[0], Detail: "swap file on target filesystem"})
			}
		}
	}
	if err := s.Err(); err != nil {
		result.Errors = append(result.Errors, "swaps: "+err.Error())
	}
}

func scanHoldersAndLoops(cfg Config, d Device, mountpoints []string, result *ScanResult) {
	for _, b := range d.Blocks {
		dirs, err := os.ReadDir(filepath.Join(cfg.SysRoot, "class", "block", b.Name, "holders"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			result.Errors = append(result.Errors, "holders "+b.Name+": "+err.Error())
		}
		for _, holder := range dirs {
			result.References = append(result.References, Reference{Kind: "block_holder", Path: b.DevNode, Detail: holder.Name()})
		}
	}
	loops, err := filepath.Glob(filepath.Join(cfg.SysRoot, "class", "block", "loop*", "loop", "backing_file"))
	if err != nil {
		result.Errors = append(result.Errors, "loop scan: "+err.Error())
		return
	}
	for _, p := range loops {
		backing := readTrim(p)
		for _, mountpoint := range mountpoints {
			if pathWithin(backing, mountpoint) {
				result.References = append(result.References, Reference{Kind: "loop_backing", Path: backing, Detail: p})
			}
		}
	}
}

func processName(procPath string) string {
	if name := readTrim(filepath.Join(procPath, "comm")); name != "" {
		return name
	}
	b, _ := os.ReadFile(filepath.Join(procPath, "cmdline"))
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func matchesTargetPath(path string, targets, mountpoints []string) bool {
	for _, target := range targets {
		if path == target || strings.TrimSuffix(path, " (deleted)") == target {
			return true
		}
	}
	for _, mountpoint := range mountpoints {
		if pathWithin(path, mountpoint) {
			return true
		}
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
