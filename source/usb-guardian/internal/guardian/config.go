package guardian

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func DefaultConfig() Config {
	return Config{
		LogLevel:             "info",
		PersistentLogging:    true,
		LogRetentionDays:     30,
		MaxLogMiB:            128,
		SysRoot:              "/sys",
		ProcRoot:             "/proc",
		DevRoot:              "/dev",
		RunRoot:              "/run",
		AllowedMountPrefixes: []string{"/mnt/disks/"},
		UDAdapter:            "/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/scripts/ud_adapter.php",
		SyslogPaths:          []string{"/var/log/syslog", "/var/log/messages"},
		LogMaxBytes:          8 << 20,
		LogKeep:              20,
		SyslogTailBytes:      64 << 10,
		SettleSeconds:        30,
		SHFSHealthSeconds:    5,
		SHFSPath:             "/mnt/user",
		EnableSGIO:           true,
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	trimmed := strings.TrimSpace(string(b))
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse JSON config: %w", err)
		}
	} else if err := parseINIConfig(trimmed, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse INI config: %w", err)
	}
	if cfg.SysRoot == "" || cfg.ProcRoot == "" || cfg.DevRoot == "" || cfg.RunRoot == "" {
		return Config{}, errors.New("sys_root, proc_root, dev_root and run_root must not be empty")
	}
	if cfg.LogMaxBytes < 64<<10 {
		return Config{}, errors.New("log_max_bytes must be at least 65536")
	}
	if cfg.LogKeep < 1 || cfg.LogKeep > 100 {
		return Config{}, errors.New("log_keep must be between 1 and 100")
	}
	if cfg.SyslogTailBytes < 0 || cfg.SyslogTailBytes > 4<<20 {
		return Config{}, errors.New("syslog_tail_bytes must be between 0 and 4194304")
	}
	if cfg.SettleSeconds < 1 || cfg.SettleSeconds > 300 {
		return Config{}, errors.New("settle_seconds must be between 1 and 300")
	}
	if cfg.SHFSHealthSeconds < 1 || cfg.SHFSHealthSeconds > 60 {
		return Config{}, errors.New("shfs_health_seconds must be between 1 and 60")
	}
	if cfg.LogRetentionDays < 1 || cfg.LogRetentionDays > 3650 {
		return Config{}, errors.New("log_retention_days must be between 1 and 3650")
	}
	if cfg.MaxLogMiB < 1 || cfg.MaxLogMiB > 16384 {
		return Config{}, errors.New("max_log_mib must be between 1 and 16384")
	}
	for _, p := range cfg.AllowedMountPrefixes {
		if !strings.HasPrefix(filepath.ToSlash(p), "/") {
			return Config{}, fmt.Errorf("allowed mount prefix %q is not absolute", p)
		}
	}
	return cfg, nil
}

func parseINIConfig(data string, cfg *Config) error {
	s := bufio.NewScanner(strings.NewReader(data))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("invalid line %q", line)
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		intValue := func() (int, error) { return strconv.Atoi(value) }
		boolValue := func() (bool, error) {
			switch strings.ToLower(value) {
			case "1", "yes", "true", "on":
				return true, nil
			case "0", "no", "false", "off":
				return false, nil
			}
			return false, fmt.Errorf("invalid boolean %q", value)
		}
		var err error
		switch key {
		case "LOG_LEVEL":
			cfg.LogLevel = strings.ToLower(value)
		case "PERSISTENT_LOGGING":
			cfg.PersistentLogging, err = boolValue()
		case "LOG_RETENTION_DAYS":
			cfg.LogRetentionDays, err = intValue()
		case "MAX_LOG_MIB":
			cfg.MaxLogMiB, err = func() (int64, error) { v, e := strconv.ParseInt(value, 10, 64); return v, e }()
		case "LOG_KEEP":
			cfg.LogKeep, err = intValue()
		case "SETTLE_SECONDS":
			cfg.SettleSeconds, err = intValue()
		case "SHFS_HEALTH_SECONDS":
			cfg.SHFSHealthSeconds, err = intValue()
		case "ENABLE_SG_IO":
			cfg.EnableSGIO, err = boolValue()
		case "TOKEN_SECRET":
			cfg.TokenSecret = value
		case "SYS_ROOT":
			cfg.SysRoot = value
		case "PROC_ROOT":
			cfg.ProcRoot = value
		case "DEV_ROOT":
			cfg.DevRoot = value
		case "RUN_ROOT":
			cfg.RunRoot = value
		case "SHFS_PATH":
			cfg.SHFSPath = value
		case "ALLOWED_MOUNT_PREFIXES":
			cfg.AllowedMountPrefixes = splitCSV(value)
		case "PROTECTED_DEVICES":
			cfg.ProtectedDevices = splitCSV(value)
		case "SYSLOG_PATHS":
			cfg.SyslogPaths = splitCSV(value)
		case "PRE_UNMOUNT_HOOK":
			if value != "" {
				cfg.PreUnmountHook = []string{value}
			}
		case "POST_UNMOUNT_HOOK":
			if value != "" {
				cfg.PostUnmountHook = []string{value}
			}
		case "UD_ADAPTER":
			cfg.UDAdapter = value
		}
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return s.Err()
}

func splitCSV(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
