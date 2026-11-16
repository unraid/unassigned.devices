package guardian

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type RecoverResult struct {
	SchemaVersion int      `json:"schema_version"`
	Recovered     []string `json:"recovered"`
	ActiveWorker  bool     `json:"active_worker,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

type RecoveryDependencies struct {
	ResolveTarget   func(Config, string) (Device, error)
	Rollback        func(context.Context, Device, string) error
	AdapterStateDir string
	RollbackTimeout time.Duration
}

type recoveryAdapterState struct {
	SchemaVersion int               `json:"schema_version"`
	JobID         string            `json:"job_id"`
	KernelName    string            `json:"kernel_name"`
	Edition       string            `json:"edition"`
	Version       string            `json:"version"`
	Device        string            `json:"device"`
	Phase         string            `json:"phase"`
	Partitions    []json.RawMessage `json:"partitions"`
}

type recoveryRollbackOutcome struct {
	Device  *Device
	Reason  *Reason
	Warning string
	Err     error
}

func RecoverInterrupted(cfg Config, jobDir, logDir string) (RecoverResult, error) {
	coordinator := UDCoordinator{Config: cfg}
	return recoverInterruptedWithDependencies(cfg, jobDir, logDir, RecoveryDependencies{
		ResolveTarget:   InspectToken,
		Rollback:        coordinator.Rollback,
		AdapterStateDir: filepath.Join(cfg.RunRoot, "ud-usb-guardian", "ud-adapter"),
		RollbackTimeout: 45 * time.Second,
	})
}

func recoverInterruptedWithDependencies(cfg Config, jobDir, logDir string, deps RecoveryDependencies) (RecoverResult, error) {
	result := RecoverResult{SchemaVersion: SchemaVersion}
	if err := verifyPersistentLogMount(cfg, logDir); err != nil {
		return result, err
	}
	if deps.ResolveTarget == nil || deps.Rollback == nil {
		return result, errors.New("recovery identity resolver and rollback hook are required")
	}
	if deps.AdapterStateDir == "" {
		deps.AdapterStateDir = filepath.Join(cfg.RunRoot, "ud-usb-guardian", "ud-adapter")
	}
	if deps.RollbackTimeout <= 0 || deps.RollbackTimeout > 2*time.Minute {
		deps.RollbackTimeout = 45 * time.Second
	}
	lock, acquired, err := acquireTransactionLock(logDir)
	if err != nil {
		return result, err
	}
	if !acquired {
		result.ActiveWorker = true
		return result, nil
	}
	defer lock.Close()
	root := filepath.Join(logDir, "transactions")
	dirs, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		activePath := filepath.Join(root, dir.Name(), "active.json")
		b, err := os.ReadFile(activePath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			result.Errors = append(result.Errors, activePath+": "+err.Error())
			continue
		}
		var marker ActiveMarker
		if err := json.Unmarshal(b, &marker); err != nil {
			result.Errors = append(result.Errors, activePath+": "+err.Error())
			continue
		}
		if marker.SchemaVersion != SchemaVersion || marker.JobID != dir.Name() || !safeID.MatchString(marker.JobID) || marker.Target == "" {
			result.Errors = append(result.Errors, activePath+": active marker identity validation failed")
			continue
		}
		journal, err := OpenJournal(logDir, marker.JobID)
		if err != nil {
			result.Errors = append(result.Errors, marker.JobID+": "+err.Error())
			continue
		}
		bootID := currentBootID(cfg)
		if marker.BootID == bootID && marker.WorkerPID > 0 && marker.WorkerStartTicks != "" && processStartTicks(cfg.ProcRoot, marker.WorkerPID) == marker.WorkerStartTicks {
			// A live worker from this boot still owns the transaction. Recovery must not race it.
			continue
		}
		if err := journal.Append(Event{Level: "error", Stage: "recovery", Type: "interrupted_by_reboot", Message: "transaction had no terminal record and was interrupted by process exit or reboot", Data: map[string]any{"started_boot_id": marker.BootID, "recovery_boot_id": bootID}}); err != nil {
			result.Errors = append(result.Errors, marker.JobID+": "+err.Error())
			continue
		}
		if _, err := journal.WriteSnapshot("boot_recovery", CaptureSnapshot(cfg, nil)); err != nil {
			result.Errors = append(result.Errors, marker.JobID+": "+err.Error())
			continue
		}
		rollback := recoverUDAdapterState(cfg, marker, bootID, journal, deps)
		job := Job{SchemaVersion: SchemaVersion, ID: marker.JobID, Status: "failed", Stage: "interrupted_by_reboot", Progress: 0, Message: "safe-eject transaction was interrupted; no automatic continuation was attempted", Target: marker.Target, StartedAt: marker.StartedAt, FinishedAt: time.Now().UTC(), Error: "interrupted_by_reboot", LogFile: journal.Path(), Terminal: true, Reasons: []Reason{{Code: "interrupted_by_reboot", Message: "the prior safe-eject transaction ended without a terminal record", Advice: "Do not assume the device is safe to unplug. Download diagnostics and inspect the last durable transaction stage."}}}
		if old, readErr := (JobStore{Dir: jobDir}).Read(marker.JobID); readErr == nil {
			job.Progress, job.Device, job.Warnings = old.Progress, old.Device, old.Warnings
			if !old.StartedAt.IsZero() {
				job.StartedAt = old.StartedAt
			}
		}
		if rollback.Device != nil {
			job.Device = rollback.Device
		}
		if rollback.Reason != nil {
			job.Reasons = append(job.Reasons, *rollback.Reason)
		}
		if rollback.Warning != "" {
			job.Warnings = append(job.Warnings, rollback.Warning)
		}
		if rollback.Err != nil {
			job.Error = "interrupted_by_reboot; UD operation barrier release unresolved: " + rollback.Err.Error()
		}
		if err := (JobStore{Dir: jobDir}).Write(job); err != nil {
			result.Errors = append(result.Errors, marker.JobID+": "+err.Error())
			continue
		}
		if rollback.Err != nil {
			// Keep active.json and the adapter state so a later recovery can retry or an operator can inspect them.
			result.Errors = append(result.Errors, marker.JobID+": "+rollback.Err.Error())
			continue
		}
		interruptedPath := filepath.Join(journal.Dir(), fmt.Sprintf("interrupted-%s.json", time.Now().UTC().Format("20060102T150405Z")))
		if err := os.Rename(activePath, interruptedPath); err != nil {
			result.Errors = append(result.Errors, marker.JobID+": "+err.Error())
			continue
		}
		if err := syncDir(journal.Dir()); err != nil {
			result.Errors = append(result.Errors, marker.JobID+": "+err.Error())
			continue
		}
		result.Recovered = append(result.Recovered, marker.JobID)
	}
	if err := rotateTransactions(logDir, cfg); err != nil {
		result.Errors = append(result.Errors, "rotation: "+err.Error())
	}
	if len(result.Errors) > 0 {
		return result, fmt.Errorf("one or more interrupted transactions could not be recovered")
	}
	return result, nil
}

func recoverUDAdapterState(cfg Config, marker ActiveMarker, currentBootID string, journal *Journal, deps RecoveryDependencies) recoveryRollbackOutcome {
	statePath := filepath.Join(deps.AdapterStateDir, marker.JobID+".json")
	info, err := os.Lstat(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return recoveryRollbackOutcome{}
	}
	if err != nil {
		return recoveryRollbackBlocked(journal, marker.JobID, "adapter state could not be inspected", err.Error())
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 2<<20 {
		return recoveryRollbackBlocked(journal, marker.JobID, "adapter state is not a bounded regular file", fmt.Sprintf("mode=%s size=%d", info.Mode(), info.Size()))
	}
	if !trustedBootID(marker.BootID) || !trustedBootID(currentBootID) {
		return recoveryRollbackBlocked(journal, marker.JobID, "a trustworthy same-boot identity is unavailable", "started_boot_id="+marker.BootID+" current_boot_id="+currentBootID)
	}
	if marker.BootID != currentBootID {
		return recoveryRollbackBlocked(journal, marker.JobID, "adapter state belongs to a different boot", "started_boot_id="+marker.BootID+" current_boot_id="+currentBootID)
	}
	b, err := os.ReadFile(statePath)
	if err != nil {
		return recoveryRollbackBlocked(journal, marker.JobID, "adapter state could not be read", err.Error())
	}
	var state recoveryAdapterState
	if err := json.Unmarshal(b, &state); err != nil {
		return recoveryRollbackBlocked(journal, marker.JobID, "adapter state JSON is invalid", err.Error())
	}
	if state.SchemaVersion != 1 || state.JobID != marker.JobID || !safeID.MatchString(state.JobID) {
		return recoveryRollbackBlocked(journal, marker.JobID, "adapter state job identity is untrusted", fmt.Sprintf("schema=%d job_id=%q", state.SchemaVersion, state.JobID))
	}
	kernelName, err := cleanKernelName(state.KernelName)
	if err != nil || kernelName != state.KernelName || state.Device != "/dev/"+kernelName {
		return recoveryRollbackBlocked(journal, marker.JobID, "adapter state kernel identity is untrusted", fmt.Sprintf("kernel=%q device=%q", state.KernelName, state.Device))
	}
	if state.Edition != "official" && state.Edition != "next" || strings.TrimSpace(state.Version) == "" || state.Partitions == nil {
		return recoveryRollbackBlocked(journal, marker.JobID, "adapter state metadata is incomplete", fmt.Sprintf("edition=%q version=%q", state.Edition, state.Version))
	}
	if state.Phase == "finalized" {
		return recoveryRollbackBlocked(journal, marker.JobID, "adapter state is already finalized", "finalized state is never rolled back")
	}
	rollbackPhases := map[string]bool{
		"prepared": true, "acquiring_ud_markers": true, "ud_markers_acquired": true,
		"removing_shares": true, "shares_removed": true,
		"running_unmount_hook": true, "hooks_run": true, "quiesced": true,
		"rollback_failed": true, "rolled_back": true,
	}
	if !rollbackPhases[state.Phase] {
		return recoveryRollbackBlocked(journal, marker.JobID, "adapter state phase is not approved for rollback", state.Phase)
	}
	device, err := deps.ResolveTarget(cfg, marker.Target)
	if err != nil || device.KernelName != kernelName {
		detail := fmt.Sprintf("expected kernel=%s", kernelName)
		if err != nil {
			detail += "; identity error=" + err.Error()
		} else {
			detail += "; resolved kernel=" + device.KernelName
		}
		return recoveryRollbackBlocked(journal, marker.JobID, "current device identity does not match adapter state", detail)
	}
	if err := journal.Append(Event{Level: "warning", Stage: "recovery", Type: "recovery_rollback_before", Message: "attempting bounded release of the UD operation barrier for a dead same-boot worker", Data: map[string]any{"phase": state.Phase, "kernel_name": kernelName, "state_file": statePath}}); err != nil {
		return recoveryRollbackOutcome{Device: &device, Reason: &Reason{Code: "recovery_rollback_failed", Message: "UD operation barrier release could not be durably started", Detail: err.Error(), Advice: "Keep the USB device connected and download diagnostics. Repair persistent logging, then normally reboot Unraid with the device still connected; refresh Unassigned Devices before retrying USB Guardian."}, Warning: err.Error(), Err: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), deps.RollbackTimeout)
	err = deps.Rollback(ctx, device, marker.JobID)
	cancel()
	if err != nil {
		_ = journal.Append(Event{Level: "error", Stage: "recovery", Type: "recovery_rollback_failed", Message: err.Error(), Data: map[string]any{"phase": state.Phase, "kernel_name": kernelName}})
		return recoveryRollbackOutcome{Device: &device, Reason: &Reason{Code: "recovery_rollback_failed", Message: "UD operation barrier could not be released after the interrupted transaction", Detail: err.Error(), Advice: "Keep the USB device connected and download diagnostics. Then normally reboot Unraid with the device still connected to clear volatile UD operation markers and complete startup recovery; refresh Unassigned Devices before retrying USB Guardian."}, Warning: "automatic UD operation barrier release failed: " + err.Error(), Err: err}
	}
	if _, statErr := os.Lstat(statePath); !errors.Is(statErr, os.ErrNotExist) {
		if statErr == nil {
			err = errors.New("UD operation barrier release returned success but adapter state still exists")
		} else {
			err = fmt.Errorf("verify UD operation barrier state removal: %w", statErr)
		}
		_ = journal.Append(Event{Level: "error", Stage: "recovery", Type: "recovery_rollback_failed", Message: err.Error(), Data: map[string]any{"phase": state.Phase, "kernel_name": kernelName}})
		return recoveryRollbackOutcome{Device: &device, Reason: &Reason{Code: "recovery_rollback_failed", Message: "UD operation barrier release completion could not be verified", Detail: err.Error(), Advice: "Keep the USB device connected and download diagnostics. Then normally reboot Unraid with the device still connected; refresh Unassigned Devices before retrying USB Guardian."}, Warning: err.Error(), Err: err}
	}
	if err := journal.Append(Event{Level: "info", Stage: "recovery", Type: "recovery_rollback_after", Message: "UD operation barrier was released for the interrupted same-boot transaction", Data: map[string]any{"phase": state.Phase, "kernel_name": kernelName}}); err != nil {
		return recoveryRollbackOutcome{Device: &device, Reason: &Reason{Code: "recovery_rollback_failed", Message: "UD operation barrier was released but its completion record could not be persisted", Detail: err.Error(), Advice: "The safe-eject transaction still failed. Keep the USB device connected, download diagnostics, and refresh Unassigned Devices before retrying USB Guardian."}, Warning: err.Error(), Err: err}
	}
	return recoveryRollbackOutcome{Device: &device, Reason: &Reason{Code: "recovery_rollback_completed", Message: "UD operation barrier was released after the interrupted transaction", Detail: "phase=" + state.Phase, Advice: "The safe-eject transaction still failed. Keep the USB device connected, refresh Unassigned Devices, and verify the device state before retrying USB Guardian."}}
}

func recoveryRollbackBlocked(journal *Journal, jobID, message, detail string) recoveryRollbackOutcome {
	err := fmt.Errorf("%s: %s", message, detail)
	appendErr := journal.Append(Event{Level: "error", Stage: "recovery", Type: "recovery_rollback_skipped", Message: message, Data: map[string]any{"detail": detail}})
	if appendErr != nil {
		err = errors.Join(err, appendErr)
	}
	return recoveryRollbackOutcome{
		Reason:  &Reason{Code: "recovery_rollback_skipped", Message: message, Detail: detail, Advice: "No automatic UD operation barrier release was attempted. Keep the USB device connected and download diagnostics. Then normally reboot Unraid with the device still connected to clear volatile UD operation markers and complete startup recovery; refresh Unassigned Devices before retrying USB Guardian."},
		Warning: "automatic UD operation barrier release skipped: " + message,
		Err:     err,
	}
}
