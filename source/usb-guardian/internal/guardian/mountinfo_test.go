package guardian

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestParseMountInfo(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "mountinfo", "nested.txt"))
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := ParseMountInfo(string(b), 123, "mnt:[9]")
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 2 {
		t.Fatalf("got %d mounts", len(mounts))
	}
	if mounts[0].MountPoint != "/mnt/disks/My USB" || mounts[0].FSType != "xfs" || mounts[0].Source != "/dev/sdb1" {
		t.Fatalf("unexpected first mount: %+v", mounts[0])
	}
	if mounts[1].PID != 123 || mounts[1].Namespace != "mnt:[9]" {
		t.Fatalf("lost process identity: %+v", mounts[1])
	}
}

func TestParseMountInfoRejectsMalformedLine(t *testing.T) {
	if _, err := ParseMountInfo("1 2 3", 1, ""); err == nil {
		t.Fatal("expected malformed mountinfo to fail closed")
	}
}

func TestEligibilityRejectsMultipleActiveTargetMounts(t *testing.T) {
	cfg := newFixtureConfig(t)
	d := addUSBFixture(t, cfg, "sdz", "8:240")
	mountinfo := fmt.Sprintf(
		"1 0 0:42 / %s rw - fuse.shfs shfs rw\n2 1 8:240 / /mnt/disks/usb-a rw - xfs /dev/sdz rw\n3 1 8:240 /nested /mnt/disks/usb-b rw - xfs /dev/sdz rw\n",
		cfg.SHFSPath,
	)
	writeFixture(t, filepath.Join(cfg.ProcRoot, "self", "mountinfo"), mountinfo)
	reasons := assessEligibility(cfg, d)
	reason := findReason(reasons, "unsupported_mount_layout")
	if reason == nil || reason.Advice == "" {
		t.Fatalf("multiple target mounts were not rejected during eligibility: %#v", reasons)
	}
}
