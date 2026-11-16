package guardian

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		t.Fatal(err)
	}
}

func newFixtureConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.SysRoot = filepath.Join(root, "sys")
	cfg.ProcRoot = filepath.Join(root, "proc")
	cfg.DevRoot = filepath.Join(root, "dev")
	cfg.RunRoot = filepath.Join(root, "run")
	cfg.SHFSPath = filepath.Join(root, "mnt", "user")
	cfg.UDAdapter = "-"
	cfg.TokenSecret = "fixture-secret"
	cfg.SHFSHealthSeconds = 0
	if err := os.MkdirAll(cfg.SHFSPath, 0755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(cfg.ProcRoot, "self", "mountinfo"), "1 0 0:42 / "+cfg.SHFSPath+" rw - fuse.shfs shfs rw\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "self", "ns", "mnt"), "mnt:[1]")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "42", "comm"), "shfs\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "42", "status"), "Name:\tshfs\nState:\tS (sleeping)\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "42", "mountinfo"), "")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "42", "ns", "mnt"), "mnt:[1]")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "swaps"), "Filename Type Size Used Priority\n")
	writeFixture(t, filepath.Join(cfg.RunRoot, "emhttp", "disks.ini"), "[inventory]\n")
	return cfg
}

func addUSBFixture(t *testing.T, cfg Config, name, majorMinor string) Device {
	t.Helper()
	block := filepath.Join(cfg.SysRoot, "class", "block", name)
	writeFixture(t, filepath.Join(block, "uevent"), "DEVTYPE=usb_device\n")
	writeFixture(t, filepath.Join(block, "idVendor"), "0781\n")
	writeFixture(t, filepath.Join(block, "idProduct"), "5581\n")
	writeFixture(t, filepath.Join(block, "serial"), "SERIAL-1\n")
	writeFixture(t, filepath.Join(block, "busnum"), "1\n")
	writeFixture(t, filepath.Join(block, "devnum"), "5\n")
	writeFixture(t, filepath.Join(block, "remove"), "")
	writeFixture(t, filepath.Join(block, "dev"), majorMinor+"\n")
	writeFixture(t, filepath.Join(block, "diskseq"), "77\n")
	writeFixture(t, filepath.Join(block, "ro"), "0\n")
	writeFixture(t, filepath.Join(block, "device", "vendor"), "SanDisk\n")
	writeFixture(t, filepath.Join(block, "device", "model"), "Ultra\n")
	if err := os.MkdirAll(filepath.Join(block, "holders"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(block, "interfaces", "1.0", "bInterfaceClass"), "08\n")
	return Device{SchemaVersion: SchemaVersion, KernelName: name, DevX: filepath.Join(cfg.DevRoot, name), MajorMinor: majorMinor, DiskSeq: "77", USBPath: filepath.ToSlash(filepath.Join("class", "block", name)), USBSerial: "SERIAL-1", Blocks: []BlockDevice{{Name: name, DevNode: filepath.Join(cfg.DevRoot, name), MajorMinor: majorMinor}}}
}
