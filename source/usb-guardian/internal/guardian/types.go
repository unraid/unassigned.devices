package guardian

import "time"

const SchemaVersion = 1

type Config struct {
	LogLevel             string   `json:"log_level,omitempty"`
	PersistentLogging    bool     `json:"persistent_logging"`
	LogRetentionDays     int      `json:"log_retention_days,omitempty"`
	MaxLogMiB            int64    `json:"max_log_mib,omitempty"`
	TokenSecret          string   `json:"token_secret,omitempty"`
	ProtectedDevices     []string `json:"protected_devices,omitempty"`
	AllowedMountPrefixes []string `json:"allowed_mount_prefixes,omitempty"`
	PreUnmountHook       []string `json:"pre_unmount_hook,omitempty"`
	PostUnmountHook      []string `json:"post_unmount_hook,omitempty"`
	UDAdapter            string   `json:"ud_adapter,omitempty"`
	SysRoot              string   `json:"sys_root,omitempty"`
	ProcRoot             string   `json:"proc_root,omitempty"`
	DevRoot              string   `json:"dev_root,omitempty"`
	RunRoot              string   `json:"run_root,omitempty"`
	SyslogPaths          []string `json:"syslog_paths,omitempty"`
	LogMaxBytes          int64    `json:"log_max_bytes,omitempty"`
	LogKeep              int      `json:"log_keep,omitempty"`
	SyslogTailBytes      int64    `json:"syslog_tail_bytes,omitempty"`
	SettleSeconds        int      `json:"settle_seconds,omitempty"`
	SHFSHealthSeconds    int      `json:"shfs_health_seconds,omitempty"`
	SHFSPath             string   `json:"shfs_path,omitempty"`
	EnableSGIO           bool     `json:"enable_sg_io,omitempty"`
}

type Reason struct {
	Code     string         `json:"code"`
	Message  string         `json:"message"`
	Detail   string         `json:"detail,omitempty"`
	Advice   string         `json:"advice,omitempty"`
	Blockers []Reference    `json:"blockers,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type Mount struct {
	PID        int    `json:"pid"`
	Namespace  string `json:"namespace,omitempty"`
	MajorMinor string `json:"major_minor"`
	Root       string `json:"root"`
	MountPoint string `json:"mount_point"`
	Options    string `json:"options,omitempty"`
	FSType     string `json:"fs_type,omitempty"`
	Source     string `json:"source,omitempty"`
}

type BlockDevice struct {
	Name       string  `json:"name"`
	DevNode    string  `json:"dev_node"`
	SysPath    string  `json:"sys_path"`
	MajorMinor string  `json:"major_minor"`
	DiskSeq    string  `json:"diskseq,omitempty"`
	Partition  bool    `json:"partition"`
	ReadOnly   bool    `json:"read_only"`
	Mounts     []Mount `json:"mounts,omitempty"`
}

type Device struct {
	SchemaVersion int           `json:"schema_version"`
	Token         string        `json:"target"`
	DevX          string        `json:"devX"`
	Aliases       []string      `json:"aliases,omitempty"`
	KernelName    string        `json:"kernel_name"`
	MajorMinor    string        `json:"major_minor"`
	DiskSeq       string        `json:"diskseq,omitempty"`
	Serial        string        `json:"serial,omitempty"`
	Vendor        string        `json:"vendor,omitempty"`
	Model         string        `json:"model,omitempty"`
	USBPath       string        `json:"usb_path"`
	USBVID        string        `json:"usb_vid,omitempty"`
	USBPID        string        `json:"usb_pid,omitempty"`
	USBSerial     string        `json:"usb_serial,omitempty"`
	USBBusNum     string        `json:"usb_busnum,omitempty"`
	USBDevNum     string        `json:"usb_devnum,omitempty"`
	Blocks        []BlockDevice `json:"blocks"`
	Eligible      bool          `json:"eligible"`
	Reasons       []Reason      `json:"reasons,omitempty"`
}

type Reference struct {
	PID       int    `json:"pid,omitempty"`
	Process   string `json:"process,omitempty"`
	Kind      string `json:"kind"`
	Path      string `json:"path,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type ScanResult struct {
	References []Reference `json:"references,omitempty"`
	Errors     []string    `json:"errors,omitempty"`
}

type Job struct {
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"job_id"`
	Status        string    `json:"state"`
	Stage         string    `json:"phase"`
	Progress      int       `json:"progress"`
	Message       string    `json:"message"`
	Target        string    `json:"target,omitempty"`
	Device        *Device   `json:"device,omitempty"`
	StartedAt     time.Time `json:"started_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
	SafeToUnplug  bool      `json:"safe_to_unplug"`
	Terminal      bool      `json:"terminal"`
	Error         string    `json:"error,omitempty"`
	Reasons       []Reason  `json:"reasons,omitempty"`
	Warnings      []string  `json:"warnings,omitempty"`
	LogFile       string    `json:"log_file,omitempty"`
}

type Event struct {
	SchemaVersion int            `json:"schema_version"`
	Time          time.Time      `json:"time"`
	JobID         string         `json:"job_id,omitempty"`
	Level         string         `json:"level"`
	Stage         string         `json:"stage,omitempty"`
	Type          string         `json:"type"`
	Message       string         `json:"message"`
	Data          map[string]any `json:"data,omitempty"`
}

type DiagnosticSnapshot struct {
	SchemaVersion int               `json:"schema_version"`
	CapturedAt    time.Time         `json:"captured_at"`
	Hostname      string            `json:"hostname,omitempty"`
	Kernel        string            `json:"kernel,omitempty"`
	Uptime        string            `json:"uptime,omitempty"`
	SHFS          SHFSHealth        `json:"shfs"`
	Files         map[string]string `json:"files,omitempty"`
	Processes     []ProcessSnapshot `json:"processes,omitempty"`
	Device        *DeviceSnapshot   `json:"device,omitempty"`
	Errors        []string          `json:"errors,omitempty"`
}

type ProcessSnapshot struct {
	PID       int    `json:"pid"`
	Comm      string `json:"comm,omitempty"`
	Namespace string `json:"mount_namespace,omitempty"`
	Status    string `json:"status,omitempty"`
	WChan     string `json:"wchan,omitempty"`
	Stack     string `json:"stack,omitempty"`
	FDCount   int    `json:"fd_count,omitempty"`
	MountInfo string `json:"mountinfo,omitempty"`
}

type DeviceSnapshot struct {
	Identity Device            `json:"identity"`
	Sysfs    map[string]string `json:"sysfs,omitempty"`
	Udev     map[string]string `json:"udev,omitempty"`
}

type SHFSHealth struct {
	PathAccessible bool              `json:"path_accessible"`
	MountVerified  bool              `json:"mount_verified"`
	MountFSType    string            `json:"mount_fs_type,omitempty"`
	MountSource    string            `json:"mount_source,omitempty"`
	MountPoints    []string          `json:"mount_points,omitempty"`
	PID            int               `json:"pid,omitempty"`
	PIDs           []int             `json:"pids,omitempty"`
	ProcessState   string            `json:"process_state,omitempty"`
	ProcessStates  map[string]string `json:"process_states,omitempty"`
	Error          string            `json:"error,omitempty"`
}
