package guardian

import (
	"path/filepath"
	"testing"
)

func TestContainerNamespaceAndSwapAreBlockers(t *testing.T) {
	cfg := newFixtureConfig(t)
	d := addUSBFixture(t, cfg, "sdz", "8:240")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "101", "comm"), "dockerd\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "101", "status"), "Name:\tdockerd\nState:\tS (sleeping)\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "101", "ns", "mnt"), "mnt:[2]")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "101", "mountinfo"), "40 25 8:240 / /mnt/disks/usb rw - xfs /dev/sdz rw\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "swaps"), "Filename Type Size Used Priority\n"+d.DevX+" partition 1024 0 -2\n")
	reasons := dynamicSafetyReasons(cfg, d, true)
	if r := findReason(reasons, "docker_bind"); r == nil || len(r.Blockers) == 0 || r.Advice == "" {
		t.Fatalf("missing docker blocker: %#v", reasons)
	}
	if r := findReason(reasons, "swap_active"); r == nil || r.Advice == "" {
		t.Fatalf("missing swap blocker: %#v", reasons)
	}
}

func TestSiblingMountIsReportedSeparately(t *testing.T) {
	cfg := newFixtureConfig(t)
	d := addUSBFixture(t, cfg, "sdz", "8:240")
	d.Blocks = append(d.Blocks, BlockDevice{Name: "sdy", DevNode: filepath.Join(cfg.DevRoot, "sdy"), MajorMinor: "8:224"})
	writeFixture(t, filepath.Join(cfg.ProcRoot, "101", "comm"), "worker\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "101", "status"), "Name:\tworker\nState:\tS (sleeping)\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "101", "ns", "mnt"), "mnt:[2]")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "101", "mountinfo"), "40 25 8:224 / /mnt/disks/sibling rw - xfs /dev/sdy rw\n")
	if r := findReason(dynamicSafetyReasons(cfg, d, true), "sibling_busy"); r == nil || r.Advice == "" {
		t.Fatalf("missing sibling_busy reason")
	}
}

func TestQEMURawUSBPassthroughIsBlocked(t *testing.T) {
	cfg := newFixtureConfig(t)
	d := addUSBFixture(t, cfg, "sdz", "8:240")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "202", "comm"), "qemu-system-x86_64\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "202", "status"), "Name:\tqemu\nState:\tS (sleeping)\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "202", "ns", "mnt"), "mnt:[1]")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "202", "mountinfo"), "")
	rawUSB := filepath.Join(cfg.DevRoot, "bus", "usb", "001", "005")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "202", "fd", "7"), rawUSB)
	reasons := dynamicSafetyReasons(cfg, d, true)
	r := findReason(reasons, "vm_passthrough")
	if r == nil || len(r.Blockers) == 0 || r.Blockers[0].Path != rawUSB {
		t.Fatalf("raw USB passthrough was not detected: %#v", reasons)
	}
}

func TestKnownFuseMountDaemonIsAllowedOnlyBeforeStrictUnmount(t *testing.T) {
	cfg := newFixtureConfig(t)
	d := addUSBFixture(t, cfg, "sdz", "8:240")
	shfsMount := "1 0 0:42 / " + cfg.SHFSPath + " rw - fuse.shfs shfs rw\n"
	usbMount := "2 0 0:55 / /mnt/disks/usb rw - fuseblk " + d.DevX + " rw\n"
	writeFixture(t, filepath.Join(cfg.ProcRoot, "self", "mountinfo"), shfsMount+usbMount)
	writeFixture(t, filepath.Join(cfg.ProcRoot, "303", "comm"), "ntfs-3g\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "303", "status"), "Name:\tntfs-3g\nState:\tS (sleeping)\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "303", "ns", "mnt"), "mnt:[1]")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "303", "mountinfo"), shfsMount+usbMount)
	writeFixture(t, filepath.Join(cfg.ProcRoot, "303", "fd", "4"), d.DevX)
	if r := findReason(dynamicSafetyReasons(cfg, d, true), "open_files"); r != nil {
		t.Fatalf("expected FUSE mount owner was treated as unrelated open file: %+v", *r)
	}
	mounts, err := targetMounts(cfg, d.Blocks)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 || mounts[0].FSType != "fuseblk" {
		t.Fatalf("FUSE source was not mapped to block device: %#v", mounts)
	}
}

func TestSwapFileOnUSBMountIsBlocked(t *testing.T) {
	cfg := newFixtureConfig(t)
	d := addUSBFixture(t, cfg, "sdz", "8:240")
	shfsMount := "1 0 0:42 / " + cfg.SHFSPath + " rw - fuse.shfs shfs rw\n"
	usbMount := "2 0 8:240 / /mnt/disks/usb rw - xfs " + d.DevX + " rw\n"
	writeFixture(t, filepath.Join(cfg.ProcRoot, "self", "mountinfo"), shfsMount+usbMount)
	writeFixture(t, filepath.Join(cfg.ProcRoot, "swaps"), "Filename Type Size Used Priority\n/mnt/disks/usb/swapfile file 1024 0 -2\n")
	mounts, err := targetMounts(cfg, d.Blocks)
	if err != nil || len(mounts) != 1 {
		t.Fatalf("target mounts unavailable: mounts=%#v err=%v", mounts, err)
	}
	scan := ScanUsage(cfg, d, true)
	if len(scan.References) == 0 {
		t.Fatalf("swap scan returned no references; mounts=%#v errors=%#v", mounts, scan.Errors)
	}
	r := findReason(dynamicSafetyReasons(cfg, d, true), "swap_active")
	if r == nil || r.Advice == "" {
		t.Fatalf("swapfile on target mount was not blocked: %#v", r)
	}
}
