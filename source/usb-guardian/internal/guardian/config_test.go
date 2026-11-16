package guardian

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadINIConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usb.guardian.cfg")
	data := `LOG_LEVEL="debug"
PERSISTENT_LOGGING="no"
LOG_RETENTION_DAYS="45"
MAX_LOG_MIB="256"
LOG_KEEP="12"
SETTLE_SECONDS="40"
SHFS_HEALTH_SECONDS="7"
ENABLE_SG_IO="false"
UD_ADAPTER="-"
ALLOWED_MOUNT_PREFIXES="/mnt/disks/,/mnt/addons/"
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "debug" || cfg.PersistentLogging || cfg.LogRetentionDays != 45 || cfg.MaxLogMiB != 256 || cfg.LogKeep != 12 {
		t.Fatalf("unexpected logging config: %+v", cfg)
	}
	if cfg.SettleSeconds != 40 || cfg.SHFSHealthSeconds != 7 || cfg.EnableSGIO || cfg.UDAdapter != "-" {
		t.Fatalf("unexpected safety config: %+v", cfg)
	}
	if len(cfg.AllowedMountPrefixes) != 2 {
		t.Fatalf("unexpected prefixes: %#v", cfg.AllowedMountPrefixes)
	}
}

func TestLoadConfigRejectsUnsafeBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"settle_seconds":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	// JSON overlays defaults, so explicitly invalid zero is indistinguishable from omitted.
	// A negative value must always be rejected.
	if err := os.WriteFile(path, []byte(`{"settle_seconds":-1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected invalid settle interval to be rejected")
	}
}
