package guardian

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverEligibleUSBAndStableToken(t *testing.T) {
	cfg := newFixtureConfig(t)
	addUSBFixture(t, cfg, "sdz", "8:240")
	devices, err := Discover(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected one USB device, got %#v", devices)
	}
	d := devices[0]
	if !d.Eligible || d.Token == "" || d.DevX != filepath.Join(cfg.DevRoot, "sdz") {
		t.Fatalf("unexpected discovery: %+v", d)
	}
	resolved, err := InspectToken(cfg, d.Token)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.DiskSeq != "77" || resolved.USBSerial != "SERIAL-1" {
		t.Fatalf("identity not preserved: %+v", resolved)
	}
}

func TestDiscoverReportsHolderWithAdvice(t *testing.T) {
	cfg := newFixtureConfig(t)
	addUSBFixture(t, cfg, "sdz", "8:240")
	holder := filepath.Join(cfg.SysRoot, "class", "block", "sdz", "holders", "dm-0")
	if err := os.MkdirAll(holder, 0755); err != nil {
		t.Fatal(err)
	}
	devices, err := Discover(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Eligible {
		t.Fatalf("holder should block eligibility: %#v", devices)
	}
	reason := findReason(devices[0].Reasons, "holder_active")
	if reason == nil || reason.Advice == "" {
		t.Fatalf("missing holder advice: %#v", devices[0].Reasons)
	}
}

func TestDiscoverProtectsBootDevice(t *testing.T) {
	cfg := newFixtureConfig(t)
	addUSBFixture(t, cfg, "sdz", "8:240")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "self", "mountinfo"), "36 25 8:240 / /boot rw - vfat /dev/sdz rw\n")
	devices, err := Discover(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Eligible {
		t.Fatalf("boot device should be blocked: %#v", devices)
	}
	if r := findReason(devices[0].Reasons, "protected_boot"); r == nil || r.Advice == "" {
		t.Fatalf("missing protected_boot reason: %#v", devices[0].Reasons)
	}
}

func TestDiscoverRejectsCompositeUSB(t *testing.T) {
	cfg := newFixtureConfig(t)
	addUSBFixture(t, cfg, "sdz", "8:240")
	writeFixture(t, filepath.Join(cfg.SysRoot, "class", "block", "sdz", "interfaces", "1.1", "bInterfaceClass"), "03\n")
	devices, err := Discover(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r := findReason(devices[0].Reasons, "composite_usb"); r == nil || r.Advice == "" {
		t.Fatalf("missing composite reason: %#v", devices[0].Reasons)
	}
}

func TestMissingUnraidInventoryAndDiskseqFailClosed(t *testing.T) {
	cfg := newFixtureConfig(t)
	addUSBFixture(t, cfg, "sdz", "8:240")
	if err := os.Remove(filepath.Join(cfg.RunRoot, "emhttp", "disks.ini")); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(cfg.SysRoot, "class", "block", "sdz", "diskseq"), "")
	devices, err := Discover(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Eligible {
		t.Fatalf("missing identity/inventory must fail closed: %#v", devices)
	}
	if r := findReason(devices[0].Reasons, "inspection_failed"); r == nil || r.Advice == "" {
		t.Fatalf("missing actionable inspection failure: %#v", devices[0].Reasons)
	}
}

func TestFinalStableIdentityChecksDiskseqAndHandleRdev(t *testing.T) {
	cfg := newFixtureConfig(t)
	addUSBFixture(t, cfg, "sdz", "8:240")
	devices, err := Discover(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("unexpected devices: %#v", devices)
	}
	handle := &fakeHandle{name: devices[0].DevX, majorMinor: "8:240"}
	if err := verifyStableIdentity(cfg, devices[0].Token, devices[0], []ExclusiveHandle{handle}); err != nil {
		t.Fatalf("stable identity rejected: %v", err)
	}
	writeFixture(t, filepath.Join(cfg.SysRoot, "class", "block", "sdz", "diskseq"), "78\n")
	if err := verifyStableIdentity(cfg, devices[0].Token, devices[0], []ExclusiveHandle{handle}); err == nil {
		t.Fatal("changed diskseq passed final identity check")
	}
}

func TestMultiLUNUSBIsBlockedUntilGroupAdapterExists(t *testing.T) {
	cfg := newFixtureConfig(t)
	d := addUSBFixture(t, cfg, "sdz", "8:240")
	d.DiskSeq, d.USBVID, d.USBPID = "77", "0781", "5581"
	d.Blocks[0].DiskSeq = "77"
	d.Blocks = append(d.Blocks, BlockDevice{Name: "sdy", DevNode: filepath.Join(cfg.DevRoot, "sdy"), MajorMinor: "8:224", DiskSeq: "78"})
	reasons := staticProtectionReasons(cfg, d)
	r := findReason(reasons, "multi_lun_usb")
	if r == nil || r.Advice == "" {
		t.Fatalf("multi-LUN USB was not blocked: %#v", reasons)
	}
}

func TestFinalIdentityRejectsNewRootLUN(t *testing.T) {
	expected := Device{USBPath: "devices/usb1/1-1", Blocks: []BlockDevice{{Name: "sdb", MajorMinor: "8:16", DiskSeq: "10"}}}
	live := []topologyEntry{
		{BlockDevice: BlockDevice{Name: "sdb", MajorMinor: "8:16", DiskSeq: "10"}, USBPath: expected.USBPath},
		{BlockDevice: BlockDevice{Name: "sdc", MajorMinor: "8:32", DiskSeq: "11"}, USBPath: expected.USBPath},
	}
	if err := verifyUSBRootSet(expected, live); err == nil {
		t.Fatal("new top-level LUN was accepted")
	}
}

func TestMissingUSBBusIdentityFailsClosed(t *testing.T) {
	cfg := newFixtureConfig(t)
	addUSBFixture(t, cfg, "sdz", "8:240")
	writeFixture(t, filepath.Join(cfg.SysRoot, "class", "block", "sdz", "busnum"), "")
	devices, err := Discover(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Eligible {
		t.Fatalf("missing busnum must block raw USB passthrough safety: %#v", devices)
	}
	r := findReason(devices[0].Reasons, "inspection_failed")
	if r == nil || !strings.Contains(r.Message, "bus/device") || r.Advice == "" {
		t.Fatalf("missing bus identity reason: %#v", devices[0].Reasons)
	}
}

func findReason(reasons []Reason, code string) *Reason {
	for i := range reasons {
		if reasons[i].Code == code {
			return &reasons[i]
		}
	}
	return nil
}
