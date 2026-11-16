package guardian

import (
	"fmt"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type PersistentLogMountError struct {
	Code    string
	Message string
	Detail  string
	Advice  string
}

func (e *PersistentLogMountError) Error() string {
	if e.Detail == "" {
		return e.Message
	}
	return e.Message + ": " + e.Detail
}

func (e *PersistentLogMountError) Reason() Reason {
	return Reason{Code: e.Code, Message: e.Message, Detail: e.Detail, Advice: e.Advice}
}

func verifyPersistentLogMount(cfg Config, logDir string) error {
	if !logPathUsesBoot(logDir) {
		return nil
	}
	mounts, err := selfMounts(cfg)
	if err != nil {
		return persistentLogMountFailure(
			"persistent_log_mount_unverified",
			"the Unraid boot mount cannot be verified before persistent logging",
			fmt.Sprintf("read %s: %v", filepath.Join(cfg.ProcRoot, "self", "mountinfo"), err),
		)
	}
	var bootMounts []Mount
	for _, mount := range mounts {
		if cleanLinuxPath(mount.MountPoint) == "/boot" {
			bootMounts = append(bootMounts, mount)
		}
	}
	if len(bootMounts) != 1 {
		return persistentLogMountFailure(
			"persistent_log_mount_missing",
			"persistent logging is unsafe because /boot is not one independent mount",
			fmt.Sprintf("found %d /boot mountinfo entries", len(bootMounts)),
		)
	}
	mount := bootMounts[0]
	fstype := strings.ToLower(strings.TrimSpace(mount.FSType))
	if !supportedBootFSType(fstype) {
		return persistentLogMountFailure(
			"persistent_log_mount_unsafe",
			"persistent logging is unsafe because /boot is not a supported FAT boot filesystem",
			fmt.Sprintf("fstype=%q source=%q major_minor=%q", mount.FSType, mount.Source, mount.MajorMinor),
		)
	}
	if mount.Root != "/" || !realBlockDeviceNumber(mount.MajorMinor) || !strings.HasPrefix(filepath.ToSlash(mount.Source), "/dev/") {
		return persistentLogMountFailure(
			"persistent_log_mount_unsafe",
			"persistent logging is unsafe because /boot is not a real top-level block-device mount",
			fmt.Sprintf("root=%q source=%q major_minor=%q fstype=%q", mount.Root, mount.Source, mount.MajorMinor, mount.FSType),
		)
	}
	if !mountOptionPresent(mount.Options, "rw") {
		return persistentLogMountFailure(
			"persistent_log_mount_read_only",
			"persistent logging is unavailable because the Unraid boot mount is not writable",
			fmt.Sprintf("options=%q source=%q fstype=%q", mount.Options, mount.Source, mount.FSType),
		)
	}
	var overlaps []string
	for _, candidate := range mounts {
		relation := logMountOverlapRelation(candidate.MountPoint, logDir)
		if relation == "" {
			continue
		}
		overlaps = append(overlaps, fmt.Sprintf(
			"mount_point=%q relation=%s fstype=%q source=%q major_minor=%q",
			candidate.MountPoint,
			relation,
			candidate.FSType,
			candidate.Source,
			candidate.MajorMinor,
		))
	}
	if len(overlaps) > 0 {
		sort.Strings(overlaps)
		return &PersistentLogMountError{
			Code:    "persistent_log_mount_overlap",
			Message: "persistent logging is unsafe because a nested mount overlaps the production log directory",
			Detail:  strings.Join(overlaps, "; "),
			Advice:  "Do not start safe eject. Ordinarily unmount the overlapping nested mount so the log directory resides directly on the Unraid boot flash, confirm Unassigned Devices has refreshed, then retry.",
		}
	}
	return nil
}

func logPathUsesBoot(value string) bool {
	clean := cleanLinuxPath(value)
	return clean == "/boot" || strings.HasPrefix(clean, "/boot/")
}

func logMountOverlapRelation(mountPoint, logDir string) string {
	mountPath := cleanLinuxPath(mountPoint)
	logPath := cleanLinuxPath(logDir)
	if mountPath == "/boot" || !pathAtOrBelow(mountPath, "/boot") {
		return ""
	}
	if mountPath == logPath {
		return "at_log_dir"
	}
	if pathAtOrBelow(logPath, mountPath) {
		return "ancestor_of_log_dir"
	}
	if pathAtOrBelow(mountPath, logPath) {
		return "inside_log_dir"
	}
	return ""
}

func cleanLinuxPath(value string) string {
	return pathpkg.Clean(filepath.ToSlash(value))
}

func pathAtOrBelow(candidate, parent string) bool {
	return candidate == parent || strings.HasPrefix(candidate, strings.TrimSuffix(parent, "/")+"/")
}

func supportedBootFSType(value string) bool {
	switch value {
	case "vfat", "msdos", "fat":
		return true
	default:
		return false
	}
}

func realBlockDeviceNumber(value string) bool {
	majorText, minorText, ok := strings.Cut(value, ":")
	if !ok {
		return false
	}
	major, majorErr := strconv.Atoi(majorText)
	minor, minorErr := strconv.Atoi(minorText)
	return majorErr == nil && minorErr == nil && major > 0 && minor >= 0
}

func mountOptionPresent(options, expected string) bool {
	for _, option := range strings.Split(options, ",") {
		if strings.TrimSpace(option) == expected {
			return true
		}
	}
	return false
}

func persistentLogMountFailure(code, message, detail string) error {
	return &PersistentLogMountError{
		Code:    code,
		Message: message,
		Detail:  detail,
		Advice:  "Do not start safe eject while /boot is unverified. Restore the Unraid boot flash as a writable FAT mount at /boot, or normally reboot Unraid and confirm the Boot Device is healthy, then retry.",
	}
}
