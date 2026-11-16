package guardian

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckSHFSRequiresVerifiedFuseMountAndRead(t *testing.T) {
	cfg := newFixtureConfig(t)
	health := CheckSHFS(cfg)
	if !shfsHealthy(health) || !health.MountVerified || health.MountFSType != "fuse.shfs" {
		t.Fatalf("valid fixture reported unhealthy: %+v", health)
	}
	writeFixture(t, filepath.Join(cfg.ProcRoot, "self", "mountinfo"), "1 0 8:1 / "+cfg.SHFSPath+" rw - xfs /dev/sda1 rw\n")
	health = CheckSHFS(cfg)
	if shfsHealthy(health) || health.MountVerified {
		t.Fatalf("non-shfs mount was accepted: %+v", health)
	}
	writeFixture(t, filepath.Join(cfg.ProcRoot, "self", "mountinfo"), "1 0 0:42 / "+cfg.SHFSPath+" rw - fuse.shfs notshfs rw\n")
	health = CheckSHFS(cfg)
	if shfsHealthy(health) || health.MountVerified {
		t.Fatalf("spoofed FUSE source was accepted: %+v", health)
	}
	writeFixture(t, filepath.Join(cfg.ProcRoot, "self", "mountinfo"), "1 0 0:42 / "+cfg.SHFSPath+" rw - fuse.other shfs rw\n")
	health = CheckSHFS(cfg)
	if shfsHealthy(health) || health.MountVerified {
		t.Fatalf("non-shfs FUSE type was accepted: %+v", health)
	}
}

func TestCheckSHFSRequiresMatchingMountAndProcessSets(t *testing.T) {
	t.Run("single", func(t *testing.T) {
		cfg := newFixtureConfig(t)
		health := CheckSHFS(cfg)
		if !shfsHealthy(health) || health.PID != 42 || health.Error != "" {
			t.Fatalf("single shfs process was not accepted: %+v", health)
		}
	})

	t.Run("multiple", func(t *testing.T) {
		cfg := newFixtureConfig(t)
		writeFixture(t, filepath.Join(cfg.ProcRoot, "self", "mountinfo"),
			"1 0 0:42 / "+cfg.SHFSPath+" rw - fuse.shfs shfs rw\n"+
				"2 0 0:43 / /mnt/user0 rw - fuse.shfs shfs rw\n")
		writeFixture(t, filepath.Join(cfg.ProcRoot, "84", "comm"), "shfs\n")
		writeFixture(t, filepath.Join(cfg.ProcRoot, "84", "status"), "Name:\tshfs\nState:\tS (sleeping)\n")
		health := CheckSHFS(cfg)
		if !shfsHealthy(health) || health.PID != 42 || len(health.PIDs) != 2 || health.Error != "" {
			t.Fatalf("matching dual shfs mounts and processes were not accepted: %+v", health)
		}
	})

	t.Run("count mismatch", func(t *testing.T) {
		cfg := newFixtureConfig(t)
		writeFixture(t, filepath.Join(cfg.ProcRoot, "84", "comm"), "shfs\n")
		writeFixture(t, filepath.Join(cfg.ProcRoot, "84", "status"), "Name:\tshfs\nState:\tS (sleeping)\n")
		health := CheckSHFS(cfg)
		if shfsHealthy(health) || !strings.Contains(health.Error, "mount/process count mismatch") {
			t.Fatalf("an unmatched shfs process was accepted: %+v", health)
		}
	})

	t.Run("none", func(t *testing.T) {
		cfg := newFixtureConfig(t)
		if err := os.RemoveAll(filepath.Join(cfg.ProcRoot, "42")); err != nil {
			t.Fatal(err)
		}
		health := CheckSHFS(cfg)
		if shfsHealthy(health) || health.PID != 0 || !strings.Contains(health.Error, "no comm=shfs") {
			t.Fatalf("missing shfs process was not rejected with an empty PID list: %+v", health)
		}
	})

	t.Run("status identity mismatch", func(t *testing.T) {
		cfg := newFixtureConfig(t)
		writeFixture(t, filepath.Join(cfg.ProcRoot, "42", "status"), "Name:\tnot-shfs\nState:\tS (sleeping)\n")
		health := CheckSHFS(cfg)
		if shfsHealthy(health) || !strings.Contains(health.Error, `status name="not-shfs"`) {
			t.Fatalf("mismatched process identity was not rejected: %+v", health)
		}
	})
}

func TestCheckSHFSWindowRequiresSamePIDSet(t *testing.T) {
	calls := 0
	healthFn := func(Config) SHFSHealth {
		calls++
		pid := 42
		if calls > 1 {
			pid = 84
		}
		return SHFSHealth{PathAccessible: true, MountVerified: true, PID: pid, ProcessState: "S (sleeping)"}
	}
	err := checkSHFSWindow(context.Background(), 1, []int{42}, Config{}, healthFn)
	if err == nil || !strings.Contains(err.Error(), "expected pids=[42], observed pids=[84]") {
		t.Fatalf("SHFS PID replacement was not rejected: calls=%d err=%v", calls, err)
	}
}

func TestSnapshotCapturesPstoreAndKernelTaint(t *testing.T) {
	cfg := newFixtureConfig(t)
	writeFixture(t, filepath.Join(cfg.SysRoot, "fs", "pstore", "dmesg-ramoops-0"), "kernel panic evidence\n")
	writeFixture(t, filepath.Join(cfg.ProcRoot, "sys", "kernel", "tainted"), "512\n")
	snapshot := CaptureSnapshot(cfg, nil)
	if snapshot.Files["pstore/dmesg-ramoops-0"] != "kernel panic evidence\n" {
		t.Fatalf("pstore evidence missing: %#v", snapshot.Files)
	}
	if snapshot.Files["proc/sys/kernel/tainted"] != "512\n" {
		t.Fatalf("kernel taint missing: %#v", snapshot.Files)
	}
}
