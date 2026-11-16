package guardian

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJobJSONContract(t *testing.T) {
	b, err := json.Marshal(Job{ID: "j1", Status: "failed", Stage: "preflight", Terminal: true, Reasons: []Reason{{Code: "open_files", Message: "busy", Advice: "close normally"}}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, key := range []string{`"job_id":"j1"`, `"state":"failed"`, `"phase":"preflight"`, `"terminal":true`, `"reasons"`} {
		if !strings.Contains(text, key) {
			t.Fatalf("missing %s in %s", key, text)
		}
	}
	for _, old := range []string{`"id":`, `"status":`, `"stage":`} {
		if strings.Contains(text, old) {
			t.Fatalf("legacy key %s in %s", old, text)
		}
	}
}

func TestJournalFsyncLifecycleAndRecovery(t *testing.T) {
	cfg := newFixtureConfig(t)
	logDir, jobDir := filepath.Join(t.TempDir(), "logs"), filepath.Join(t.TempDir(), "jobs")
	j, err := NewJournal(logDir, jobDir, "recover-me", "opaque", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Append(Event{Level: "info", Stage: "pre_remove", Type: "sentinel", Message: "must survive"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	} // Simulate OS releasing the flock after a crash.
	running := Job{ID: "recover-me", Status: "running", Stage: "usb_remove", Progress: 75, Target: "opaque", StartedAt: time.Now().Add(-time.Minute)}
	if err := (JobStore{Dir: jobDir}).Write(running); err != nil {
		t.Fatal(err)
	}
	result, err := RecoverInterrupted(cfg, jobDir, logDir)
	if err != nil {
		t.Fatalf("recover failed: %v (%+v)", err, result)
	}
	if len(result.Recovered) != 1 || result.Recovered[0] != "recover-me" {
		t.Fatalf("unexpected result: %+v", result)
	}
	job, err := (JobStore{Dir: jobDir}).Read("recover-me")
	if err != nil {
		t.Fatal(err)
	}
	if !job.Terminal || job.Status != "failed" || job.Stage != "interrupted_by_reboot" || job.SafeToUnplug {
		t.Fatalf("unsafe recovered job: %+v", job)
	}
	b, err := os.ReadFile(j.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "must survive") || !strings.Contains(string(b), "interrupted_by_reboot") || !strings.Contains(string(b), "boot_recovery") {
		t.Fatalf("timeline was overwritten or incomplete: %s", b)
	}
	if fileExists(filepath.Join(j.Dir(), "active.json")) {
		t.Fatal("active marker not converted after recovery")
	}
	matches, _ := filepath.Glob(filepath.Join(j.Dir(), "interrupted-*.json"))
	if len(matches) != 1 {
		t.Fatalf("missing preserved interruption marker: %#v", matches)
	}
}

func TestActiveTransactionIsNeverRotated(t *testing.T) {
	cfg := newFixtureConfig(t)
	cfg.LogKeep = 1
	cfg.MaxLogMiB = 1
	cfg.LogRetentionDays = 1
	logDir := filepath.Join(t.TempDir(), "logs")
	j, err := NewJournal(logDir, t.TempDir(), "active-job", "opaque", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(j.Dir(), old, old)
	if err := rotateTransactions(logDir, cfg); err != nil {
		t.Fatal(err)
	}
	if !fileExists(filepath.Join(j.Dir(), "active.json")) {
		t.Fatal("rotation deleted active transaction")
	}
}

func TestRecoveryDoesNotInterruptLiveWorkerOnSameBoot(t *testing.T) {
	cfg := newFixtureConfig(t)
	writeFixture(t, filepath.Join(cfg.ProcRoot, "sys", "kernel", "random", "boot_id"), "same-boot\n")
	pid := os.Getpid()
	writeFixture(t, filepath.Join(cfg.ProcRoot, fmt.Sprint(pid), "stat"), fmt.Sprintf("%d (usb-guardian) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 1 0 987654 0 0 0 0\n", pid))
	logDir, jobDir := filepath.Join(t.TempDir(), "logs"), filepath.Join(t.TempDir(), "jobs")
	j, err := NewJournal(logDir, jobDir, "still-running", "opaque", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	} // Exercise same-boot PID/start-time protection independently of flock.
	result, err := RecoverInterrupted(cfg, jobDir, logDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Recovered) != 0 {
		t.Fatalf("live job was incorrectly recovered: %+v", result)
	}
	if !fileExists(filepath.Join(j.Dir(), "active.json")) {
		t.Fatal("live worker active marker was removed")
	}
}

func TestGlobalTransactionLockRejectsConcurrentWorkerAndRecovery(t *testing.T) {
	cfg := newFixtureConfig(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	j, err := NewJournal(logDir, t.TempDir(), "first-job", "opaque", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := NewJournal(logDir, t.TempDir(), "second-job", "opaque", cfg); err == nil {
		t.Fatal("concurrent transaction acquired global lock")
	}
	result, err := RecoverInterrupted(cfg, t.TempDir(), logDir)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ActiveWorker || len(result.Recovered) != 0 {
		t.Fatalf("recovery raced live transaction: %+v", result)
	}
}

func TestRootServiceLogsAreRotatedWithinBudget(t *testing.T) {
	cfg := newFixtureConfig(t)
	cfg.MaxLogMiB = 1
	cfg.LogKeep = 3
	logDir := filepath.Join(t.TempDir(), "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "api.log"), make([]byte, 200<<10), 0644); err != nil {
		t.Fatal(err)
	}
	if err := rotateTransactions(logDir, cfg); err != nil {
		t.Fatal(err)
	}
	if !fileExists(filepath.Join(logDir, "api.log.1")) {
		t.Fatal("api.log was not rotated")
	}
	if fileExists(filepath.Join(logDir, "api.log")) {
		t.Fatal("oversized active api.log remained")
	}
}

func newInterruptedRecoveryFixture(t *testing.T, phase string) (Config, string, string, string, string) {
	t.Helper()
	cfg := newFixtureConfig(t)
	writeFixture(t, filepath.Join(cfg.ProcRoot, "sys", "kernel", "random", "boot_id"), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n")
	logDir, jobDir := filepath.Join(t.TempDir(), "logs"), filepath.Join(t.TempDir(), "jobs")
	jobID := "recover-rollback"
	j, err := NewJournal(logDir, jobDir, jobID, "opaque-token", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(cfg.RunRoot, "ud-usb-guardian", "ud-adapter")
	statePath := filepath.Join(stateDir, jobID+".json")
	state := recoveryAdapterState{SchemaVersion: 1, JobID: jobID, KernelName: "sdz", Edition: "official", Version: "2025.11.18", Device: "/dev/sdz", Phase: phase, Partitions: []json.RawMessage{}}
	if err := atomicWriteJSON(statePath, state, 0600); err != nil {
		t.Fatal(err)
	}
	return cfg, logDir, jobDir, stateDir, statePath
}

func TestSameBootRecoveryRollsBackTrustedAdapterState(t *testing.T) {
	cfg, logDir, jobDir, stateDir, statePath := newInterruptedRecoveryFixture(t, "quiesced")
	rollbackCalls := 0
	deps := RecoveryDependencies{
		AdapterStateDir: stateDir,
		ResolveTarget:   func(Config, string) (Device, error) { return Device{KernelName: "sdz"}, nil },
		Rollback: func(ctx context.Context, d Device, jobID string) error {
			rollbackCalls++
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("rollback context has no deadline")
			}
			if d.KernelName != "sdz" || jobID != "recover-rollback" {
				t.Fatalf("wrong rollback identity: %+v %s", d, jobID)
			}
			return os.Remove(statePath)
		},
		RollbackTimeout: 2 * time.Second,
	}
	result, err := recoverInterruptedWithDependencies(cfg, jobDir, logDir, deps)
	if err != nil {
		t.Fatalf("recovery failed: %v (%+v)", err, result)
	}
	if rollbackCalls != 1 || len(result.Recovered) != 1 {
		t.Fatalf("trusted rollback not completed: calls=%d result=%+v", rollbackCalls, result)
	}
	job, err := (JobStore{Dir: jobDir}).Read("recover-rollback")
	if err != nil {
		t.Fatal(err)
	}
	reason := findReason(job.Reasons, "recovery_rollback_completed")
	if reason == nil {
		t.Fatalf("rollback result missing from job: %#v", job.Reasons)
	}
	if !strings.Contains(reason.Message, "operation barrier was released") || !strings.Contains(reason.Advice, "still failed") || !strings.Contains(reason.Advice, "refresh Unassigned Devices") {
		t.Fatalf("rollback result misstates narrow adapter behavior: %+v", reason)
	}
	timeline, err := os.ReadFile(filepath.Join(logDir, "transactions", "recover-rollback", "timeline.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(timeline), "recovery_rollback_before") || !strings.Contains(string(timeline), "recovery_rollback_after") || !strings.Contains(string(timeline), "operation barrier was released") || strings.Contains(string(timeline), "share state") {
		t.Fatalf("rollback timeline incomplete: %s", timeline)
	}
}

func TestRecoveryRejectsMissingOrUnknownBootIdentity(t *testing.T) {
	for _, markerBootID := range []string{"", "unknown", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		t.Run(fmt.Sprintf("marker_%q", markerBootID), func(t *testing.T) {
			cfg, logDir, jobDir, stateDir, statePath := newInterruptedRecoveryFixture(t, "quiesced")
			if err := os.Remove(filepath.Join(cfg.ProcRoot, "sys", "kernel", "random", "boot_id")); err != nil {
				t.Fatal(err)
			}
			activePath := filepath.Join(logDir, "transactions", "recover-rollback", "active.json")
			contents, err := os.ReadFile(activePath)
			if err != nil {
				t.Fatal(err)
			}
			var marker ActiveMarker
			if err := json.Unmarshal(contents, &marker); err != nil {
				t.Fatal(err)
			}
			marker.BootID = markerBootID
			if err := atomicWriteJSON(activePath, marker, 0640); err != nil {
				t.Fatal(err)
			}
			rollbackCalls := 0
			result, err := recoverInterruptedWithDependencies(cfg, jobDir, logDir, RecoveryDependencies{
				AdapterStateDir: stateDir,
				ResolveTarget:   func(Config, string) (Device, error) { return Device{KernelName: "sdz"}, nil },
				Rollback:        func(context.Context, Device, string) error { rollbackCalls++; return nil },
			})
			if err == nil || rollbackCalls != 0 || len(result.Errors) == 0 {
				t.Fatalf("untrusted boot identity reached rollback: calls=%d result=%+v err=%v", rollbackCalls, result, err)
			}
			if !fileExists(statePath) || !fileExists(activePath) {
				t.Fatal("untrusted boot identity did not preserve recovery state")
			}
			job, readErr := (JobStore{Dir: jobDir}).Read("recover-rollback")
			if readErr != nil {
				t.Fatal(readErr)
			}
			reason := findReason(job.Reasons, "recovery_rollback_skipped")
			if reason == nil || !strings.Contains(reason.Message, "boot identity") {
				t.Fatalf("untrusted boot identity reason is missing: %#v", job.Reasons)
			}
		})
	}
}

func TestRecoveryRollbackPhasePolicy(t *testing.T) {
	for _, phase := range []string{"prepared", "acquiring_ud_markers", "ud_markers_acquired", "removing_shares", "shares_removed", "running_unmount_hook", "hooks_run", "quiesced", "rollback_failed", "rolled_back"} {
		t.Run("allows_"+phase, func(t *testing.T) {
			cfg, logDir, jobDir, stateDir, statePath := newInterruptedRecoveryFixture(t, phase)
			calls := 0
			result, err := recoverInterruptedWithDependencies(cfg, jobDir, logDir, RecoveryDependencies{
				AdapterStateDir: stateDir,
				ResolveTarget:   func(Config, string) (Device, error) { return Device{KernelName: "sdz"}, nil },
				Rollback: func(context.Context, Device, string) error {
					calls++
					return os.Remove(statePath)
				},
			})
			if err != nil || calls != 1 || len(result.Recovered) != 1 {
				t.Fatalf("approved phase was not recovered: calls=%d result=%+v err=%v", calls, result, err)
			}
		})
	}

	for _, phase := range []string{"releasing_ud_markers", "marker_release_failed", "finalized", "unknown"} {
		t.Run("blocks_"+phase, func(t *testing.T) {
			cfg, logDir, jobDir, stateDir, statePath := newInterruptedRecoveryFixture(t, phase)
			calls := 0
			result, err := recoverInterruptedWithDependencies(cfg, jobDir, logDir, RecoveryDependencies{
				AdapterStateDir: stateDir,
				ResolveTarget:   func(Config, string) (Device, error) { return Device{KernelName: "sdz"}, nil },
				Rollback:        func(context.Context, Device, string) error { calls++; return nil },
			})
			if err == nil || calls != 0 || len(result.Errors) == 0 || !fileExists(statePath) {
				t.Fatalf("unsafe phase was not preserved: calls=%d result=%+v err=%v", calls, result, err)
			}
		})
	}
}

func TestRecoveryNeverRollsBackFinalizedOrMismatchedState(t *testing.T) {
	for _, tc := range []struct {
		name, phase string
		resolve     func(Config, string) (Device, error)
	}{
		{name: "finalized", phase: "finalized", resolve: func(Config, string) (Device, error) { return Device{KernelName: "sdz"}, nil }},
		{name: "identity_mismatch", phase: "quiesced", resolve: func(Config, string) (Device, error) { return Device{}, errors.New("token identity changed") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, logDir, jobDir, stateDir, statePath := newInterruptedRecoveryFixture(t, tc.phase)
			rollbackCalls := 0
			result, err := recoverInterruptedWithDependencies(cfg, jobDir, logDir, RecoveryDependencies{AdapterStateDir: stateDir, ResolveTarget: tc.resolve, Rollback: func(context.Context, Device, string) error { rollbackCalls++; return nil }})
			if err == nil || len(result.Errors) == 0 {
				t.Fatalf("unresolved state should fail recovery: %+v", result)
			}
			if rollbackCalls != 0 {
				t.Fatal("unsafe rollback was attempted")
			}
			if !fileExists(statePath) || !fileExists(filepath.Join(logDir, "transactions", "recover-rollback", "active.json")) {
				t.Fatal("unresolved forensic/rollback state was removed")
			}
			job, readErr := (JobStore{Dir: jobDir}).Read("recover-rollback")
			if readErr != nil {
				t.Fatal(readErr)
			}
			if findReason(job.Reasons, "recovery_rollback_skipped") == nil || len(job.Warnings) == 0 {
				t.Fatalf("skip not exposed in job: %+v", job)
			}
		})
	}
}

func TestRecoveryRejectsAdapterDevicePathAlias(t *testing.T) {
	cfg, logDir, jobDir, stateDir, statePath := newInterruptedRecoveryFixture(t, "quiesced")
	state := recoveryAdapterState{SchemaVersion: 1, JobID: "recover-rollback", KernelName: "sdz", Edition: "official", Version: "2025.11.18", Device: "/tmp/sdz", Phase: "quiesced", Partitions: []json.RawMessage{}}
	if err := atomicWriteJSON(statePath, state, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	result, err := recoverInterruptedWithDependencies(cfg, jobDir, logDir, RecoveryDependencies{
		AdapterStateDir: stateDir,
		ResolveTarget:   func(Config, string) (Device, error) { return Device{KernelName: "sdz"}, nil },
		Rollback:        func(context.Context, Device, string) error { calls++; return nil },
	})
	if err == nil || calls != 0 || len(result.Errors) == 0 || !fileExists(statePath) {
		t.Fatalf("device path alias was not rejected: calls=%d result=%+v err=%v", calls, result, err)
	}
}

func TestRecoveryRollbackFailurePreservesRetryState(t *testing.T) {
	cfg, logDir, jobDir, stateDir, statePath := newInterruptedRecoveryFixture(t, "shares_removed")
	result, err := recoverInterruptedWithDependencies(cfg, jobDir, logDir, RecoveryDependencies{
		AdapterStateDir: stateDir,
		ResolveTarget:   func(Config, string) (Device, error) { return Device{KernelName: "sdz"}, nil },
		Rollback:        func(context.Context, Device, string) error { return errors.New("UD operation barrier release failed") },
	})
	if err == nil || len(result.Errors) == 0 {
		t.Fatalf("rollback failure should fail recovery: %+v", result)
	}
	if !fileExists(statePath) || !fileExists(filepath.Join(logDir, "transactions", "recover-rollback", "active.json")) {
		t.Fatal("rollback retry state was removed")
	}
	job, readErr := (JobStore{Dir: jobDir}).Read("recover-rollback")
	if readErr != nil {
		t.Fatal(readErr)
	}
	reason := findReason(job.Reasons, "recovery_rollback_failed")
	if reason == nil || len(job.Warnings) == 0 {
		t.Fatalf("rollback failure not exposed: %+v", job)
	}
	if !strings.Contains(reason.Message, "operation barrier could not be released") || !strings.Contains(reason.Advice, "Keep the USB device connected") || !strings.Contains(reason.Advice, "refresh Unassigned Devices") {
		t.Fatalf("rollback failure misstates narrow adapter behavior: %+v", reason)
	}
	timeline, readErr := os.ReadFile(filepath.Join(logDir, "transactions", "recover-rollback", "timeline.jsonl"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(timeline), "recovery_rollback_before") || !strings.Contains(string(timeline), "recovery_rollback_failed") {
		t.Fatalf("rollback failure timeline incomplete: %s", timeline)
	}
}
