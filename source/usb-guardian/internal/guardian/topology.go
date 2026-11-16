package guardian

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type topologyEntry struct {
	BlockDevice
	USBPath string
}

func Discover(cfg Config) ([]Device, error) {
	entries, err := readTopology(cfg)
	if err != nil {
		return nil, err
	}
	groups := make(map[string][]topologyEntry)
	for _, e := range entries {
		if e.USBPath != "" {
			groups[e.USBPath] = append(groups[e.USBPath], e)
		}
	}
	var devices []Device
	for usbPath, group := range groups {
		sort.Slice(group, func(i, j int) bool {
			if group[i].Partition != group[j].Partition {
				return !group[i].Partition
			}
			return group[i].Name < group[j].Name
		})
		blocks := make([]BlockDevice, 0, len(group))
		for _, g := range group {
			blocks = append(blocks, g.BlockDevice)
		}
		for _, root := range group {
			if root.Partition {
				continue
			}
			d := makeDevice(cfg, root, usbPath, blocks)
			d.Reasons = assessEligibility(cfg, d)
			d.Eligible = len(d.Reasons) == 0
			d.Token, err = encodeToken(cfg, d)
			if err != nil {
				return nil, err
			}
			devices = append(devices, d)
		}
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].KernelName < devices[j].KernelName })
	return devices, nil
}

func assessEligibility(cfg Config, d Device) []Reason {
	reasons := staticProtectionReasons(cfg, d)
	if mounts, err := targetMounts(cfg, d.Blocks); err != nil {
		reasons = appendReason(reasons, Reason{Code: "inspection_failed", Message: "the active USB mount layout could not be inspected", Detail: err.Error(), Advice: "Keep the device connected and restore access to the self mount table before retrying."})
	} else if reason := unsupportedMountLayoutReason(mounts); reason != nil {
		reasons = appendReason(reasons, *reason)
	}
	reasons = append(reasons, dynamicSafetyReasons(cfg, d, true)...)
	health := CheckSHFS(cfg)
	if !shfsHealthy(health) {
		reasons = appendReason(reasons, Reason{Code: "shfs_unhealthy", Message: "shfs is not healthy before safe eject", Detail: health.Error + " state=" + health.ProcessState, Advice: "Do not unplug the device. Collect diagnostics and restore normal /mnt/user access before retrying."})
	}
	if err := (UDCoordinator{Config: cfg}).Inspect(context.Background(), d, "list"); err != nil {
		reasons = appendReason(reasons, udInspectionReason(err))
	}
	return reasons
}

func InspectToken(cfg Config, token string) (Device, error) {
	p, err := decodeToken(cfg, token)
	if err != nil {
		return Device{}, err
	}
	devices, err := Discover(cfg)
	if err != nil {
		return Device{}, err
	}
	for _, d := range devices {
		if d.KernelName != p.KernelName {
			continue
		}
		if d.MajorMinor != p.MajorMinor || d.DiskSeq != p.DiskSeq || d.USBPath != p.USBPath || d.USBSerial != p.USBSerial || d.USBBusNum != p.USBBusNum || d.USBDevNum != p.USBDevNum {
			return Device{}, errors.New("target identity changed since discovery")
		}
		return d, nil
	}
	return Device{}, errors.New("target device is no longer present")
}

func verifyStableIdentity(cfg Config, token string, expected Device, handles []ExclusiveHandle) error {
	p, err := decodeToken(cfg, token)
	if err != nil {
		return err
	}
	classDirs, err := os.ReadDir(filepath.Join(cfg.SysRoot, "class", "block"))
	if err != nil {
		return err
	}
	for _, dir := range classDirs {
		classPath := filepath.Join(cfg.SysRoot, "class", "block", dir.Name())
		realPath, resolveErr := filepath.EvalSymlinks(classPath)
		if resolveErr != nil {
			return fmt.Errorf("final topology parse %s: %w", dir.Name(), resolveErr)
		}
		if usbPath := findUSBDeviceAncestor(cfg.SysRoot, realPath); usbPath == expected.USBPath && readTrim(filepath.Join(classPath, "dev")) == "" {
			return fmt.Errorf("target USB block %s has no device number", dir.Name())
		}
	}
	entries, err := readTopology(cfg)
	if err != nil {
		return err
	}
	byName := make(map[string]*topologyEntry)
	for i := range entries {
		byName[entries[i].Name] = &entries[i]
	}
	current := byName[expected.KernelName]
	if current == nil {
		return errors.New("target block device disappeared during final identity check")
	}
	if current.MajorMinor != expected.MajorMinor || current.DiskSeq == "" || current.DiskSeq != expected.DiskSeq || current.USBPath != expected.USBPath {
		return fmt.Errorf("block identity changed: expected dev=%s diskseq=%s usb=%s, current dev=%s diskseq=%s usb=%s", expected.MajorMinor, expected.DiskSeq, expected.USBPath, current.MajorMinor, current.DiskSeq, current.USBPath)
	}
	if p.KernelName != current.Name || p.MajorMinor != current.MajorMinor || p.DiskSeq != current.DiskSeq || p.USBPath != current.USBPath {
		return errors.New("target token no longer matches the current block identity")
	}
	if err := verifyUSBRootSet(expected, entries); err != nil {
		return err
	}
	usb := filepath.Join(cfg.SysRoot, filepath.FromSlash(current.USBPath))
	vid, pid, serial := readTrim(filepath.Join(usb, "idVendor")), readTrim(filepath.Join(usb, "idProduct")), readTrim(filepath.Join(usb, "serial"))
	busnum, devnum := readTrim(filepath.Join(usb, "busnum")), readTrim(filepath.Join(usb, "devnum"))
	if vid != expected.USBVID || pid != expected.USBPID || serial != expected.USBSerial || serial != p.USBSerial || busnum != expected.USBBusNum || devnum != expected.USBDevNum || busnum != p.USBBusNum || devnum != p.USBDevNum {
		return fmt.Errorf("USB identity changed: expected %s:%s serial=%q, current %s:%s serial=%q", expected.USBVID, expected.USBPID, expected.USBSerial, vid, pid, serial)
	}
	expectedMM := make(map[string]string)
	for _, b := range expected.Blocks {
		if !b.Partition {
			expectedMM[b.DevNode] = b.MajorMinor
		}
	}
	if len(handles) != len(expectedMM) {
		return errors.New("exclusive handle count does not match top-level USB block devices")
	}
	for _, handle := range handles {
		want, ok := expectedMM[handle.Name()]
		if !ok {
			return fmt.Errorf("unexpected exclusive handle %s", handle.Name())
		}
		got, err := handle.MajorMinor()
		if err != nil {
			return fmt.Errorf("fstat %s: %w", handle.Name(), err)
		}
		if got != want {
			return fmt.Errorf("exclusive handle identity changed for %s: expected %s, got %s", handle.Name(), want, got)
		}
	}
	return nil
}

func verifyUSBRootSet(expected Device, entries []topologyEntry) error {
	expectedRoots := make(map[string]BlockDevice)
	for _, block := range expected.Blocks {
		if !block.Partition {
			expectedRoots[block.Name] = block
		}
	}
	liveRoots := make(map[string]topologyEntry)
	for _, live := range entries {
		if live.USBPath == expected.USBPath && !live.Partition {
			liveRoots[live.Name] = live
		}
	}
	if len(liveRoots) != len(expectedRoots) {
		return fmt.Errorf("top-level USB block set changed: expected %d, current %d", len(expectedRoots), len(liveRoots))
	}
	for name, block := range expectedRoots {
		live, ok := liveRoots[name]
		if !ok || live.MajorMinor != block.MajorMinor || live.DiskSeq == "" || live.DiskSeq != block.DiskSeq {
			return fmt.Errorf("sibling block identity changed for %s", block.Name)
		}
	}
	return nil
}

func readTopology(cfg Config) ([]topologyEntry, error) {
	base := filepath.Join(cfg.SysRoot, "class", "block")
	dirs, err := os.ReadDir(base)
	if err != nil {
		return nil, fmt.Errorf("read block topology: %w", err)
	}
	var out []topologyEntry
	for _, dir := range dirs {
		name, err := cleanKernelName(dir.Name())
		if err != nil {
			continue
		}
		classPath := filepath.Join(base, name)
		realPath, err := filepath.EvalSymlinks(classPath)
		if err != nil {
			continue
		}
		usbPath := findUSBDeviceAncestor(cfg.SysRoot, realPath)
		if usbPath == "" {
			continue
		}
		dev := readTrim(filepath.Join(classPath, "dev"))
		if dev == "" {
			continue
		}
		out = append(out, topologyEntry{BlockDevice: BlockDevice{
			Name: name, DevNode: filepath.Join(cfg.DevRoot, name), SysPath: realPath,
			MajorMinor: dev, DiskSeq: readTrim(filepath.Join(classPath, "diskseq")),
			Partition: fileExists(filepath.Join(classPath, "partition")),
			ReadOnly:  readTrim(filepath.Join(classPath, "ro")) == "1",
		}, USBPath: usbPath})
	}
	return out, nil
}

func findUSBDeviceAncestor(sysRoot, start string) string {
	sysRoot, _ = filepath.Abs(sysRoot)
	cur, _ := filepath.Abs(start)
	for {
		kv := readKV(filepath.Join(cur, "uevent"))
		if kv["DEVTYPE"] == "usb_device" || (fileExists(filepath.Join(cur, "idVendor")) && fileExists(filepath.Join(cur, "idProduct"))) {
			rel, err := filepath.Rel(sysRoot, cur)
			if err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
				return filepath.ToSlash(rel)
			}
			return ""
		}
		next := filepath.Dir(cur)
		if next == cur || !pathWithin(cur, sysRoot) {
			return ""
		}
		cur = next
	}
}

func makeDevice(cfg Config, root topologyEntry, usbPath string, blocks []BlockDevice) Device {
	usbAbs := filepath.Join(cfg.SysRoot, filepath.FromSlash(usbPath))
	serial := readTrim(filepath.Join(root.SysPath, "device", "serial"))
	usbSerial := readTrim(filepath.Join(usbAbs, "serial"))
	if serial == "" {
		serial = usbSerial
	}
	d := Device{
		SchemaVersion: SchemaVersion, DevX: root.DevNode, KernelName: root.Name,
		Aliases:    deviceAliases(cfg.DevRoot, root.Name),
		MajorMinor: root.MajorMinor, DiskSeq: root.DiskSeq, Serial: serial,
		Vendor:  strings.TrimSpace(readTrim(filepath.Join(root.SysPath, "device", "vendor"))),
		Model:   strings.TrimSpace(readTrim(filepath.Join(root.SysPath, "device", "model"))),
		USBPath: usbPath, USBVID: readTrim(filepath.Join(usbAbs, "idVendor")),
		USBPID: readTrim(filepath.Join(usbAbs, "idProduct")), USBSerial: usbSerial, Blocks: blocks,
		USBBusNum: readTrim(filepath.Join(usbAbs, "busnum")), USBDevNum: readTrim(filepath.Join(usbAbs, "devnum")),
	}
	if mounts, err := targetMounts(cfg, blocks); err == nil {
		for i := range d.Blocks {
			for _, m := range mounts {
				if m.MajorMinor == d.Blocks[i].MajorMinor {
					d.Blocks[i].Mounts = append(d.Blocks[i].Mounts, m)
				}
			}
		}
	}
	return d
}

func deviceAliases(devRoot, kernelName string) []string {
	var aliases []string
	dirs, _ := filepath.Glob(filepath.Join(devRoot, "disk", "by-*"))
	for _, dir := range dirs {
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			target, err := os.Readlink(path)
			if err != nil {
				continue
			}
			if filepath.Base(target) == kernelName {
				aliases = append(aliases, path)
			}
		}
	}
	return uniqueStrings(aliases)
}

func staticProtectionReasons(cfg Config, d Device) []Reason {
	var reasons []Reason
	rootBlocks := 0
	for _, block := range d.Blocks {
		if !block.Partition {
			rootBlocks++
		}
	}
	if rootBlocks > 1 {
		reasons = appendReason(reasons, Reason{Code: "multi_lun_usb", Message: "the same physical USB device contains multiple disks or LUNs", Detail: fmt.Sprintf("%d top-level block devices", rootBlocks), Advice: "Normally unmount every member of this enclosure and do not use USB Guardian for it in this release."})
	}
	if d.DiskSeq == "" {
		reasons = appendReason(reasons, Reason{Code: "inspection_failed", Message: "kernel disk sequence identity is unavailable", Advice: "Do not eject this device with USB Guardian on this kernel; collect diagnostics and leave it connected."})
	}
	for _, block := range d.Blocks {
		if !block.Partition && block.DiskSeq == "" {
			reasons = appendReason(reasons, Reason{Code: "inspection_failed", Message: "a sibling disk sequence identity is unavailable", Detail: block.Name, Advice: "Leave the entire USB enclosure connected and collect diagnostics before retrying."})
		}
	}
	if d.USBVID == "" || d.USBPID == "" {
		reasons = appendReason(reasons, Reason{Code: "inspection_failed", Message: "USB vendor/product identity is unavailable", Advice: "Wait for USB discovery to complete and retry; otherwise collect diagnostics and leave it connected."})
	}
	if parseInt(d.USBBusNum) <= 0 || parseInt(d.USBDevNum) <= 0 {
		reasons = appendReason(reasons, Reason{Code: "inspection_failed", Message: "USB bus/device identity is unavailable", Detail: "busnum=" + d.USBBusNum + " devnum=" + d.USBDevNum, Advice: "Wait for USB discovery to complete; raw USB VM/container passthrough cannot be ruled out without this identity."})
	}
	for _, protected := range cfg.ProtectedDevices {
		p := filepath.Base(protected)
		for _, b := range d.Blocks {
			if p == b.Name || protected == b.DevNode || protected == b.MajorMinor {
				reasons = appendReason(reasons, Reason{Code: "configured_protected", Message: "device is explicitly protected", Detail: protected, Advice: "Remove the protection only after confirming this is not an array, pool, boot, VM, or service device."})
			}
		}
	}
	usbAbs := filepath.Join(cfg.SysRoot, filepath.FromSlash(d.USBPath))
	if !fileExists(filepath.Join(usbAbs, "remove")) {
		reasons = appendReason(reasons, Reason{Code: "inspection_failed", Message: "physical USB device does not expose a remove control", Advice: "Leave the device connected; this USB controller cannot be safely handled by the plugin."})
	}
	if r := compositeInterfaceReason(usbAbs); r != nil {
		reasons = appendReason(reasons, *r)
	}
	for _, b := range d.Blocks {
		if holders, _ := os.ReadDir(filepath.Join(cfg.SysRoot, "class", "block", b.Name, "holders")); len(holders) > 0 {
			var names []string
			for _, h := range holders {
				names = append(names, h.Name())
			}
			reasons = appendReason(reasons, Reason{Code: "holder_active", Message: "a device-mapper, RAID or other block holder is active", Detail: b.Name + ":" + strings.Join(names, ","), Advice: "Deactivate the mapped volume or pool using its owning storage tool, then retry."})
		}
	}
	reasons = append(reasons, bootAndSystemReasons(cfg, d)...)
	reasons = append(reasons, unraidAssignmentReasons(cfg, d)...)
	reasons = append(reasons, btrfsPoolReasons(cfg, d)...)
	return reasons
}

func compositeInterfaceReason(usbAbs string) *Reason {
	base := filepath.Base(usbAbs) + ":"
	dirs, err := os.ReadDir(usbAbs)
	if err != nil {
		return &Reason{Code: "inspection_failed", Message: "cannot verify USB interface composition", Detail: err.Error(), Advice: "Leave the device connected and review the diagnostic bundle."}
	}
	seenStorage := false
	var interfaces []string
	for _, d := range dirs {
		if !d.IsDir() || !strings.HasPrefix(d.Name(), base) {
			continue
		}
		interfaces = append(interfaces, filepath.Join(usbAbs, d.Name()))
	}
	if fixtureInterfaces, fixtureErr := os.ReadDir(filepath.Join(usbAbs, "interfaces")); fixtureErr == nil {
		for _, d := range fixtureInterfaces {
			if d.IsDir() {
				interfaces = append(interfaces, filepath.Join(usbAbs, "interfaces", d.Name()))
			}
		}
	}
	for _, interfacePath := range interfaces {
		class := strings.ToLower(readTrim(filepath.Join(interfacePath, "bInterfaceClass")))
		if class == "08" {
			seenStorage = true
			continue
		}
		if class == "" {
			return &Reason{Code: "inspection_failed", Message: "cannot identify every USB interface", Detail: filepath.Base(interfacePath), Advice: "Leave the device connected and review the USB interface descriptors."}
		}
		return &Reason{Code: "composite_usb", Message: "USB device has a non-storage interface", Detail: filepath.Base(interfacePath) + " class=" + class, Advice: "Do not use per-disk safe eject for this composite device; disconnect its other functions through their normal controls first."}
	}
	if !seenStorage {
		return &Reason{Code: "inspection_failed", Message: "USB mass-storage interface was not found", Advice: "Leave the device connected and review USB topology diagnostics."}
	}
	return nil
}

func bootAndSystemReasons(cfg Config, d Device) []Reason {
	mounts, err := selfMounts(cfg)
	if err != nil {
		return []Reason{{Code: "inspection_failed", Message: "cannot verify protected system mounts", Detail: err.Error(), Advice: "Restore access to /proc mount information before retrying."}}
	}
	devs := make(map[string]bool)
	for _, b := range d.Blocks {
		devs[b.MajorMinor] = true
	}
	var out []Reason
	for _, m := range mounts {
		if !devs[m.MajorMinor] && !mountSourceMatches(m.Source, d.Blocks) {
			continue
		}
		if m.MountPoint == "/boot" || m.MountPoint == "/" || strings.HasPrefix(m.MountPoint, "/boot/") {
			out = appendReason(out, Reason{Code: "protected_boot", Message: "device contains the Unraid boot or root filesystem", Detail: m.MountPoint, Advice: "The Unraid boot device must never be ejected while the server is running."})
		}
		allowed := false
		for _, prefix := range cfg.AllowedMountPrefixes {
			if pathWithin(m.MountPoint, strings.TrimSuffix(prefix, "/")) {
				allowed = true
				break
			}
		}
		if !allowed && m.MountPoint != "/boot" && m.MountPoint != "/" {
			out = appendReason(out, Reason{Code: "inspection_failed", Message: "device is mounted outside an approved Unassigned Devices path", Detail: m.MountPoint, Advice: "Unmount it normally from the application that created this mount, then retry."})
		}
	}
	return out
}

func unraidAssignmentReasons(cfg Config, d Device) []Reason {
	paths := []string{filepath.Join(cfg.RunRoot, "emhttp", "disks.ini"), "/var/local/emhttp/disks.ini"}
	var content string
	readable := 0
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			content += "\n" + string(b)
			readable++
		}
	}
	var out []Reason
	if readable == 0 {
		return []Reason{{Code: "inspection_failed", Message: "Unraid assigned-disk inventory could not be read", Detail: strings.Join(paths, ", "), Advice: "Wait for emhttp disk inventory initialization or restore its runtime files before retrying."}}
	}
	if strings.TrimSpace(content) == "" {
		return []Reason{{Code: "inspection_failed", Message: "Unraid assigned-disk inventory is empty", Advice: "Wait for emhttp disk inventory initialization before retrying."}}
	}
	target := make(map[string]bool)
	for _, b := range d.Blocks {
		target[b.Name] = true
	}
	section := ""
	s := bufio.NewScanner(strings.NewReader(content))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.ToLower(strings.TrimSpace(key)) != "device" {
			continue
		}
		device := strings.Trim(strings.TrimSpace(value), `"'`)
		if !target[filepath.Base(device)] {
			continue
		}
		code, message, advice := "protected_pool", "device is assigned to an Unraid pool", "Remove the device only through Unraid pool management; do not eject an assigned pool member."
		switch {
		case section == "flash":
			code, message, advice = "protected_boot", "device is the Unraid boot flash", "The Unraid boot flash must never be ejected while the server is running."
		case strings.HasPrefix(section, "disk") || strings.HasPrefix(section, "parity"):
			code, message, advice = "protected_array", "device is assigned to the Unraid array", "Remove the assignment only through Unraid array management; do not eject an assigned device."
		}
		out = appendReason(out, Reason{Code: code, Message: message, Detail: section + ":" + device, Advice: advice})
	}
	return out
}

func btrfsPoolReasons(cfg Config, d Device) []Reason {
	base := filepath.Join(cfg.SysRoot, "fs", "btrfs")
	filesystems, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	target := make(map[string]bool)
	for _, b := range d.Blocks {
		target[b.MajorMinor] = true
	}
	var out []Reason
	for _, fs := range filesystems {
		devDirs, _ := os.ReadDir(filepath.Join(base, fs.Name(), "devices"))
		if len(devDirs) < 2 {
			continue
		}
		for _, devDir := range devDirs {
			mm := readTrim(filepath.Join(base, fs.Name(), "devices", devDir.Name(), "dev"))
			if target[mm] {
				out = appendReason(out, Reason{Code: "protected_pool", Message: "device belongs to a multi-device Btrfs filesystem", Detail: fs.Name(), Advice: "Remove or export the device through the pool's normal management workflow before ejecting it."})
			}
		}
	}
	return out
}

func appendReason(in []Reason, reason Reason) []Reason {
	for _, r := range in {
		if r.Code == reason.Code && r.Detail == reason.Detail {
			return in
		}
	}
	return append(in, reason)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
