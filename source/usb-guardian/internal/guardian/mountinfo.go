package guardian

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func ParseMountInfo(data string, pid int, namespace string) ([]Mount, error) {
	var out []Mount
	s := bufio.NewScanner(strings.NewReader(data))
	line := 0
	for s.Scan() {
		line++
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		fields := strings.Fields(s.Text())
		if len(fields) < 10 {
			return nil, fmt.Errorf("mountinfo line %d has too few fields", line)
		}
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+3 >= len(fields) {
			return nil, fmt.Errorf("mountinfo line %d has no separator", line)
		}
		out = append(out, Mount{
			PID: pid, Namespace: namespace, MajorMinor: fields[2], Root: unescapeMount(fields[3]),
			MountPoint: unescapeMount(fields[4]), Options: fields[5], FSType: fields[sep+1],
			Source: unescapeMount(fields[sep+2]),
		})
	}
	return out, s.Err()
}

func readMountInfo(procRoot string, pid int) ([]Mount, error) {
	ns, _ := readMountNamespace(procRoot, strconv.Itoa(pid))
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "mountinfo"))
	if err != nil {
		return nil, err
	}
	return ParseMountInfo(string(b), pid, ns)
}

func selfMounts(cfg Config) ([]Mount, error) {
	b, err := os.ReadFile(filepath.Join(cfg.ProcRoot, "self", "mountinfo"))
	if err != nil {
		return nil, err
	}
	ns, _ := readMountNamespace(cfg.ProcRoot, "self")
	return ParseMountInfo(string(b), os.Getpid(), ns)
}

func readMountNamespace(procRoot, pid string) (string, error) {
	path := filepath.Join(procRoot, pid, "ns", "mnt")
	ns, err := os.Readlink(path)
	if err == nil {
		return ns, nil
	}
	if filepath.Clean(procRoot) != filepath.Clean("/proc") {
		if value := readTrim(path); value != "" {
			return value, nil
		}
	}
	return "", err
}

func targetMounts(cfg Config, blocks []BlockDevice) ([]Mount, error) {
	all, err := selfMounts(cfg)
	if err != nil {
		return nil, err
	}
	devs := make(map[string]bool)
	for _, b := range blocks {
		devs[b.MajorMinor] = true
	}
	var out []Mount
	for _, m := range all {
		if devs[m.MajorMinor] || mountSourceMatches(m.Source, blocks) {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Count(out[i].MountPoint, "/") > strings.Count(out[j].MountPoint, "/")
	})
	return out, nil
}

func unsupportedMountLayoutReason(mounts []Mount) *Reason {
	if len(mounts) <= 1 {
		return nil
	}
	details := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		detail := mount.MountPoint
		if mount.MajorMinor != "" {
			detail += " (" + mount.MajorMinor + ")"
		}
		details = append(details, detail)
	}
	sort.Strings(details)
	return &Reason{
		Code:    "unsupported_mount_layout",
		Message: "the USB device has more than one active target mount",
		Detail:  strings.Join(details, ", "),
		Advice:  "Use Unassigned Devices to ordinarily unmount the extra target mount or all target mounts, then use USB Guardian to complete logical USB removal.",
	}
}

func mountSourceMatches(source string, blocks []BlockDevice) bool {
	if source == "" || source == "none" {
		return false
	}
	resolved := source
	if path, err := filepath.EvalSymlinks(source); err == nil {
		resolved = path
	}
	for _, block := range blocks {
		if source == block.DevNode || resolved == block.DevNode || filepath.Base(resolved) == block.Name {
			return true
		}
	}
	return false
}
