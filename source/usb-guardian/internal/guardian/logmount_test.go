package guardian

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

const productionLogPath = "/boot/config/plugins/unassigned.devices/usb-guardian/logs"

const validBootMount = "36 25 8:1 / /boot rw,relatime - vfat /dev/sda1 rw"

func setBootMountInfo(t *testing.T, cfg Config, line string) {
	t.Helper()
	contents := "1 0 0:42 / " + cfg.SHFSPath + " rw - fuse.shfs shfs rw\n"
	if line != "" {
		contents += line + "\n"
	}
	writeFixture(t, filepath.Join(cfg.ProcRoot, "self", "mountinfo"), contents)
}

func requirePersistentMountError(t *testing.T, err error, code string) *PersistentLogMountError {
	t.Helper()
	var mountErr *PersistentLogMountError
	if !errors.As(err, &mountErr) {
		t.Fatalf("expected PersistentLogMountError, got %T: %v", err, err)
	}
	if mountErr.Code != code || mountErr.Advice == "" {
		t.Fatalf("unexpected persistent mount error: %+v", mountErr)
	}
	return mountErr
}

func TestPersistentLogMountRejectsMissingBootMount(t *testing.T) {
	cfg := newFixtureConfig(t)
	setBootMountInfo(t, cfg, "")
	err := verifyPersistentLogMount(cfg, productionLogPath)
	requirePersistentMountError(t, err, "persistent_log_mount_missing")

	_, recoverErr := recoverInterruptedWithDependencies(cfg, t.TempDir(), productionLogPath, RecoveryDependencies{})
	requirePersistentMountError(t, recoverErr, "persistent_log_mount_missing")
}

func TestPersistentLogMountRejectsWrongFilesystem(t *testing.T) {
	cfg := newFixtureConfig(t)
	setBootMountInfo(t, cfg, "36 25 8:1 / /boot rw,relatime - ext4 /dev/sda1 rw")
	err := verifyPersistentLogMount(cfg, productionLogPath)
	mountErr := requirePersistentMountError(t, err, "persistent_log_mount_unsafe")
	if !strings.Contains(mountErr.Detail, `fstype="ext4"`) {
		t.Fatalf("filesystem diagnosis is incomplete: %+v", mountErr)
	}
}

func TestPersistentLogMountRejectsPseudoOrReadOnlyFAT(t *testing.T) {
	for _, tc := range []struct {
		name, line, code string
	}{
		{name: "pseudo", line: "36 25 0:42 / /boot rw,relatime - vfat none rw", code: "persistent_log_mount_unsafe"},
		{name: "bind_root", line: "36 25 8:1 /config /boot rw,relatime - vfat /dev/sda1 rw", code: "persistent_log_mount_unsafe"},
		{name: "read_only", line: "36 25 8:1 / /boot ro,relatime - vfat /dev/sda1 ro", code: "persistent_log_mount_read_only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newFixtureConfig(t)
			setBootMountInfo(t, cfg, tc.line)
			requirePersistentMountError(t, verifyPersistentLogMount(cfg, productionLogPath), tc.code)
		})
	}
}

func TestPersistentLogMountAcceptsConservativeFATNames(t *testing.T) {
	for _, fstype := range []string{"vfat", "msdos", "fat"} {
		t.Run(fstype, func(t *testing.T) {
			cfg := newFixtureConfig(t)
			setBootMountInfo(t, cfg, "36 25 8:1 / /boot rw,relatime - "+fstype+" /dev/sda1 rw")
			if err := verifyPersistentLogMount(cfg, productionLogPath); err != nil {
				t.Fatalf("valid %s boot mount was rejected: %v", fstype, err)
			}
		})
	}
}

func TestPersistentLogMountRejectsOverlappingNestedMounts(t *testing.T) {
	for _, tc := range []struct {
		name, mountPoint, relation string
	}{
		{name: "ancestor", mountPoint: "/boot/config", relation: "ancestor_of_log_dir"},
		{name: "inside", mountPoint: productionLogPath + "/transactions", relation: "inside_log_dir"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newFixtureConfig(t)
			nested := "37 36 8:2 / " + tc.mountPoint + " rw,relatime - ext4 /dev/sdb1 rw"
			setBootMountInfo(t, cfg, validBootMount+"\n"+nested)
			mountErr := requirePersistentMountError(t, verifyPersistentLogMount(cfg, productionLogPath), "persistent_log_mount_overlap")
			if !strings.Contains(mountErr.Detail, `mount_point="`+tc.mountPoint+`"`) || !strings.Contains(mountErr.Detail, "relation="+tc.relation) || !strings.Contains(mountErr.Detail, `source="/dev/sdb1"`) {
				t.Fatalf("nested mount diagnosis is incomplete: %+v", mountErr)
			}
			if !strings.Contains(mountErr.Advice, "unmount the overlapping nested mount") {
				t.Fatalf("nested mount advice is not actionable: %+v", mountErr)
			}
		})
	}
}

func TestPersistentLogMountAllowsUnrelatedBootSubmount(t *testing.T) {
	cfg := newFixtureConfig(t)
	unrelated := "37 36 8:2 / /boot/config-backup rw,relatime - ext4 /dev/sdb1 rw"
	setBootMountInfo(t, cfg, validBootMount+"\n"+unrelated)
	if err := verifyPersistentLogMount(cfg, productionLogPath); err != nil {
		t.Fatalf("unrelated /boot submount was rejected: %v", err)
	}
}

func TestPersistentLogMountDoesNotRestrictTemporaryLogs(t *testing.T) {
	cfg := newFixtureConfig(t)
	setBootMountInfo(t, cfg, validBootMount+"\n37 36 8:2 / /boot/config rw,relatime - ext4 /dev/sdb1 rw")
	if err := verifyPersistentLogMount(cfg, filepath.Join(t.TempDir(), "logs")); err != nil {
		t.Fatalf("temporary log directory was incorrectly boot-gated: %v", err)
	}
}

func TestEjectReportsStructuredBootMountFailure(t *testing.T) {
	cfg := newFixtureConfig(t)
	setBootMountInfo(t, cfg, "")
	job, err := (Ejector{Config: cfg}).Run(context.Background(), EjectRequest{
		Target: "opaque",
		JobID:  "boot-log-guard",
		JobDir: t.TempDir(),
		LogDir: productionLogPath,
	})
	if err == nil || !job.Terminal || job.SafeToUnplug {
		t.Fatalf("unsafe boot mount did not stop eject: job=%+v err=%v", job, err)
	}
	if reason := findReason(job.Reasons, "persistent_log_mount_missing"); reason == nil || reason.Advice == "" {
		t.Fatalf("boot mount failure is not structured: %#v", job.Reasons)
	}
}
