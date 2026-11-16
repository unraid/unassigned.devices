package guardian

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type ActiveMarker struct {
	SchemaVersion    int       `json:"schema_version"`
	JobID            string    `json:"job_id"`
	JobDir           string    `json:"job_dir"`
	Target           string    `json:"target"`
	StartedAt        time.Time `json:"started_at"`
	BootID           string    `json:"boot_id,omitempty"`
	WorkerPID        int       `json:"worker_pid,omitempty"`
	WorkerStartTicks string    `json:"worker_start_ticks,omitempty"`
}

type Journal struct {
	mu       sync.Mutex
	dir      string
	path     string
	active   string
	jobID    string
	logRoot  string
	lock     io.Closer
	lockOnce sync.Once
}

func NewJournal(logDir, jobDir, jobID, target string, cfg Config) (*Journal, error) {
	if !safeID.MatchString(jobID) {
		return nil, errors.New("invalid job id")
	}
	if logDir == "" {
		return nil, errors.New("log directory is required")
	}
	if err := verifyPersistentLogMount(cfg, logDir); err != nil {
		return nil, err
	}
	lock, acquired, err := acquireTransactionLock(logDir)
	if err != nil {
		return nil, fmt.Errorf("acquire global transaction lock: %w", err)
	}
	if !acquired {
		return nil, errors.New("another USB Guardian transaction is active")
	}
	releaseLock := true
	defer func() {
		if releaseLock {
			_ = lock.Close()
		}
	}()
	if err := rotateTransactions(logDir, cfg); err != nil {
		return nil, err
	}
	dir := filepath.Join(logDir, "transactions", jobID)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	j := &Journal{dir: dir, path: filepath.Join(dir, "timeline.jsonl"), active: filepath.Join(dir, "active.json"), jobID: jobID, logRoot: logDir, lock: lock}
	marker := ActiveMarker{SchemaVersion: SchemaVersion, JobID: jobID, JobDir: jobDir, Target: target, StartedAt: time.Now().UTC(), BootID: currentBootID(cfg), WorkerPID: os.Getpid()}
	marker.WorkerStartTicks = processStartTicks(cfg.ProcRoot, marker.WorkerPID)
	if err := atomicWriteJSON(j.active, marker, 0640); err != nil {
		return nil, err
	}
	if err := j.Append(Event{Level: "info", Stage: "start", Type: "transaction_started", Message: "persistent transaction marker created", Data: map[string]any{"boot_id": marker.BootID}}); err != nil {
		return nil, err
	}
	releaseLock = false
	return j, nil
}

func processStartTicks(procRoot string, pid int) string {
	data := readTrim(filepath.Join(procRoot, fmt.Sprint(pid), "stat"))
	end := strings.LastIndex(data, ")")
	if end < 0 || end+1 >= len(data) {
		return ""
	}
	fields := strings.Fields(data[end+1:])
	if len(fields) <= 19 {
		return ""
	}
	return fields[19]
}

func OpenJournal(logDir, jobID string) (*Journal, error) {
	if !safeID.MatchString(jobID) {
		return nil, errors.New("invalid job id")
	}
	dir := filepath.Join(logDir, "transactions", jobID)
	return &Journal{dir: dir, path: filepath.Join(dir, "timeline.jsonl"), active: filepath.Join(dir, "active.json"), jobID: jobID, logRoot: logDir}, nil
}

func (j *Journal) Append(e Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	e.SchemaVersion = SchemaVersion
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.JobID == "" {
		e.JobID = j.jobID
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(b)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func (j *Journal) WriteSnapshot(stage string, snapshot DiagnosticSnapshot) (string, error) {
	stage = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, strings.ToLower(stage))
	name := fmt.Sprintf("snapshot-%s-%s.json", time.Now().UTC().Format("20060102T150405.000000000Z"), stage)
	path := filepath.Join(j.dir, name)
	if err := atomicWriteJSON(path, snapshot, 0640); err != nil {
		return "", err
	}
	if err := j.Append(Event{Level: "info", Stage: stage, Type: "diagnostic_snapshot", Message: "diagnostic snapshot persisted", Data: map[string]any{"file": name, "shfs": snapshot.SHFS}}); err != nil {
		return "", err
	}
	return path, nil
}

func (j *Journal) Finish(status, message string) error {
	if err := j.Append(Event{Level: "info", Stage: "terminal", Type: status, Message: message}); err != nil {
		return err
	}
	if err := os.Remove(j.active); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDir(j.dir); err != nil {
		return err
	}
	return j.Close()
}

func (j *Journal) Close() error {
	var err error
	j.lockOnce.Do(func() {
		if j.lock != nil {
			err = j.lock.Close()
			j.lock = nil
		}
	})
	return err
}

func (j *Journal) Path() string { return j.path }
func (j *Journal) Dir() string  { return j.dir }

type JobStore struct{ Dir string }

func (s JobStore) path(id string) (string, error) {
	if !safeID.MatchString(id) {
		return "", errors.New("invalid job id")
	}
	if s.Dir == "" {
		return "", errors.New("job directory is required")
	}
	return filepath.Join(s.Dir, id+".json"), nil
}

func (s JobStore) Write(job Job) error {
	path, err := s.path(job.ID)
	if err != nil {
		return err
	}
	job.SchemaVersion = SchemaVersion
	job.UpdatedAt = time.Now().UTC()
	return atomicWriteJSON(path, job, 0640)
}

func (s JobStore) Read(id string) (Job, error) {
	path, err := s.path(id)
	if err != nil {
		return Job{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Job{}, err
	}
	var job Job
	if err := json.Unmarshal(b, &job); err != nil {
		return Job{}, err
	}
	return job, nil
}

func atomicWriteJSON(path string, value any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(path)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}

type transactionInfo struct {
	path   string
	mod    time.Time
	size   int64
	active bool
}

type rootLogInfo struct {
	path   string
	mod    time.Time
	size   int64
	active bool
}

func rotateTransactions(logDir string, cfg Config) error {
	if err := verifyPersistentLogMount(cfg, logDir); err != nil {
		return err
	}
	root := filepath.Join(logDir, "transactions")
	if err := os.MkdirAll(root, 0750); err != nil {
		return err
	}
	dirs, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	rootLogs, err := rotateRootLogs(logDir, cfg)
	if err != nil {
		return err
	}
	var infos []transactionInfo
	var total int64
	for _, info := range rootLogs {
		total += info.size
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		path := filepath.Join(root, d.Name())
		activePath := filepath.Join(path, "active.json")
		_, activeErr := os.Lstat(activePath)
		if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
			return fmt.Errorf("inspect active transaction marker %s: %w", activePath, activeErr)
		}
		info := transactionInfo{path: path, active: activeErr == nil}
		walkErr := filepath.Walk(path, func(_ string, fi os.FileInfo, visitErr error) error {
			if visitErr != nil {
				return visitErr
			}
			if !fi.IsDir() {
				info.size += fi.Size()
				if fi.ModTime().After(info.mod) {
					info.mod = fi.ModTime()
				}
			}
			return nil
		})
		if walkErr != nil {
			return fmt.Errorf("inspect transaction log %s: %w", path, walkErr)
		}
		total += info.size
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, k int) bool { return infos[i].mod.Before(infos[k].mod) })
	cutoff := time.Now().Add(-time.Duration(cfg.LogRetentionDays) * 24 * time.Hour)
	max := cfg.MaxLogMiB << 20
	remaining := len(infos)
	for _, info := range infos {
		if info.active {
			continue
		}
		remove := info.mod.Before(cutoff) || total > max || remaining > cfg.LogKeep
		if !remove {
			continue
		}
		if err := os.RemoveAll(info.path); err != nil {
			return err
		}
		total -= info.size
		remaining--
	}
	if total > max {
		sort.Slice(rootLogs, func(i, k int) bool { return rootLogs[i].mod.Before(rootLogs[k].mod) })
		for _, info := range rootLogs {
			if total <= max {
				break
			}
			if info.active {
				continue
			}
			if err := os.Remove(info.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			total -= info.size
		}
	}
	return errors.Join(syncDir(root), syncDir(logDir))
}

func MaintainLogs(logDir string, cfg Config) error {
	if err := verifyPersistentLogMount(cfg, logDir); err != nil {
		return err
	}
	lock, acquired, err := acquireTransactionLock(logDir)
	if err != nil {
		return err
	}
	if !acquired {
		return nil
	}
	defer lock.Close()
	return rotateTransactions(logDir, cfg)
}

func rotateRootLogs(logDir string, cfg Config) ([]rootLogInfo, error) {
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return nil, err
	}
	maxTotal := cfg.MaxLogMiB << 20
	perFile := maxTotal / 8
	if perFile < 64<<10 {
		perFile = 64 << 10
	}
	keep := cfg.LogKeep
	if keep > 5 {
		keep = 5
	}
	if keep < 1 {
		keep = 1
	}
	names := []string{"api.log", "ud-adapter.log", "launcher.log", "service.log"}
	for _, name := range names {
		path := filepath.Join(logDir, name)
		st, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if st.Size() <= perFile {
			continue
		}
		for i := keep - 1; i >= 1; i-- {
			from, to := fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1)
			_ = os.Remove(to)
			if err := os.Rename(from, to); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
		_ = os.Remove(path + ".1")
		if err := os.Rename(path, path+".1"); err != nil {
			return nil, err
		}
	}
	cutoff := time.Now().Add(-time.Duration(cfg.LogRetentionDays) * 24 * time.Hour)
	var out []rootLogInfo
	for _, name := range names {
		basePath := filepath.Join(logDir, name)
		matches, _ := filepath.Glob(basePath + ".*")
		for _, match := range matches {
			suffix := strings.TrimPrefix(match, basePath+".")
			if n, parseErr := strconv.Atoi(suffix); parseErr == nil && n > keep {
				_ = os.Remove(match)
			}
		}
		for i := 0; i <= keep; i++ {
			path := filepath.Join(logDir, name)
			active := i == 0
			if i > 0 {
				path = fmt.Sprintf("%s.%d", path, i)
			}
			st, err := os.Stat(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !active && st.ModTime().Before(cutoff) {
				if err := os.Remove(path); err != nil {
					return nil, err
				}
				continue
			}
			out = append(out, rootLogInfo{path: path, mod: st.ModTime(), size: st.Size(), active: active})
		}
	}
	if err := syncDir(logDir); err != nil {
		return nil, err
	}
	return out, nil
}
