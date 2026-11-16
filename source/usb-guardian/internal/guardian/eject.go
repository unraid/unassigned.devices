package guardian

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

type EjectRequest struct {
	Target string
	JobID  string
	JobDir string
	LogDir string
}

type Ejector struct {
	Config             Config
	Ops                SystemOps
	Coordinator        Coordinator
	Now                func() time.Time
	ResolveTarget      func(Config, string) (Device, error)
	Capture            func(Config, *Device) DiagnosticSnapshot
	Health             func(Config) SHFSHealth
	Safety             func(Config, Device, bool) []Reason
	Mounts             func(Config, []BlockDevice) ([]Mount, error)
	WaitRemoved        func(Config, Device, time.Duration) error
	VerifyIdentity     func(Config, string, Device, []ExclusiveHandle) error
	FinalSafety        func(Config, Device, []ExclusiveHandle) []Reason
	PostFinalizeSafety func(Config, Device) []Reason
}

func (e Ejector) Run(ctx context.Context, req EjectRequest) (Job, error) {
	if req.Target == "" || req.JobDir == "" || req.LogDir == "" || !safeID.MatchString(req.JobID) {
		return Job{}, errors.New("target, valid job-id, job-dir and log-dir are required")
	}
	if e.Ops == nil {
		e.Ops = DefaultSystemOps{}
	}
	if e.Coordinator == nil {
		e.Coordinator = UDCoordinator{Config: e.Config}
	}
	if e.Now == nil {
		e.Now = func() time.Time { return time.Now().UTC() }
	}
	if e.ResolveTarget == nil {
		e.ResolveTarget = InspectToken
	}
	if e.Capture == nil {
		e.Capture = CaptureSnapshot
	}
	if e.Health == nil {
		e.Health = CheckSHFS
	}
	if e.Safety == nil {
		e.Safety = dynamicSafetyReasons
	}
	if e.Mounts == nil {
		e.Mounts = targetMounts
	}
	if e.WaitRemoved == nil {
		e.WaitRemoved = waitForRemoval
	}
	if e.VerifyIdentity == nil {
		e.VerifyIdentity = verifyStableIdentity
	}
	if e.FinalSafety == nil {
		e.FinalSafety = finalSafetyReasons
	}
	if e.PostFinalizeSafety == nil {
		e.PostFinalizeSafety = transactionSafetyReasons
	}
	store := JobStore{Dir: req.JobDir}
	job := Job{SchemaVersion: SchemaVersion, ID: req.JobID, Status: "running", Stage: "start", Message: "starting safe-eject transaction", Target: req.Target, StartedAt: e.Now()}
	job.UpdatedAt = job.StartedAt
	if err := store.Write(job); err != nil {
		return job, fmt.Errorf("create job: %w", err)
	}
	journal, err := NewJournal(req.LogDir, req.JobDir, req.JobID, req.Target, e.Config)
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		reason := Reason{Code: "persistent_log_failed", Message: "persistent transaction logging could not be started", Detail: err.Error(), Advice: "Do not eject the device. Verify the boot flash log directory is writable, then retry."}
		var mountErr *PersistentLogMountError
		if errors.As(err, &mountErr) {
			reason = mountErr.Reason()
		}
		job.Reasons = []Reason{reason}
		job.Terminal = true
		job.FinishedAt = e.Now()
		job.UpdatedAt = job.FinishedAt
		_ = store.Write(job)
		return job, fmt.Errorf("create persistent transaction log: %w", err)
	}
	defer journal.Close()
	job.LogFile = journal.Path()
	_ = store.Write(job)
	var d Device
	quiesceAttempted, quiesced, finalized, removed := false, false, false, false
	rollbackProhibited, strictlyUnmounted, recoveryPending := false, false, false
	var stopUEvent func()
	var handles []ExclusiveHandle
	fail := func(stage string, cause error) (Job, error) {
		adapterPhase := ""
		irreversibleAdapterFailure := false
		var adapterErr *UDAdapterError
		if errors.As(cause, &adapterErr) {
			adapterPhase = adapterErr.Phase
			if adapterErr.IsIrreversible() {
				irreversibleAdapterFailure = true
				rollbackProhibited = true
				strictlyUnmounted = true
			}
		}
		if stopUEvent != nil {
			stopUEvent()
			stopUEvent = nil
		}
		if !removed && len(handles) > 0 {
			if closeErr := closeHandles(handles); closeErr != nil {
				job.Warnings = append(job.Warnings, "close exclusive handles before rollback: "+closeErr.Error())
			}
			handles = nil
		}
		var rollbackReason *Reason
		recordRollbackSkipped := func(message, detail, advice string, data map[string]any) {
			recoveryPending = true
			job.Warnings = append(job.Warnings, message+": "+detail)
			rollbackReason = &Reason{Code: "rollback_skipped", Message: message, Detail: detail, Advice: advice}
			if data == nil {
				data = make(map[string]any)
			}
			data["adapter_phase"] = adapterPhase
			if err := journal.Append(Event{Level: "error", Stage: stage, Type: "rollback_skipped", Message: message, Data: data}); err != nil {
				job.Warnings = append(job.Warnings, "durable rollback_skipped record failed: "+err.Error())
			}
		}
		if quiesceAttempted && !removed && d.KernelName != "" {
			if rollbackProhibited {
				if irreversibleAdapterFailure || (strictlyUnmounted && !finalized) {
					message := "UD operation barrier release was skipped because the adapter crossed its irreversible boundary"
					detail := "phase=" + adapterPhase
					if !irreversibleAdapterFailure {
						message = "UD operation barrier release was skipped because ordinary unmount already completed"
						detail = "ordinary unmount completed; UD operation barrier release is deferred to finalization or startup recovery"
					}
					recordRollbackSkipped(
						message,
						detail,
						"Keep the USB device connected and download diagnostics. Then, with the device still connected, normally reboot Unraid to clear volatile UD operation markers and complete startup recovery; refresh Unassigned Devices before retrying USB Guardian.",
						nil,
					)
				}
			} else {
				fresh, identityErr := e.ResolveTarget(e.Config, req.Target)
				if identityErr == nil {
					identityErr = validateRollbackIdentity(req.Target, d, fresh)
				}
				if identityErr != nil {
					recordRollbackSkipped(
						"UD operation barrier release was skipped because the target identity is no longer trusted",
						identityErr.Error(),
						"Keep the USB device connected and download diagnostics; do not run UD recovery against an unverified device. Then normally reboot Unraid with the device still connected to clear volatile UD operation markers and complete startup recovery; refresh Unassigned Devices before retrying USB Guardian.",
						map[string]any{"expected": rollbackIdentityData(d)},
					)
				} else {
					d = fresh
					job.Device = &d
					before := Event{Level: "warning", Stage: stage, Type: "rollback_before", Message: "starting bounded UD operation barrier release after target identity revalidation", Data: map[string]any{"identity": rollbackIdentityData(d)}}
					if beforeErr := journal.Append(before); beforeErr != nil {
						recordRollbackSkipped(
							"UD operation barrier release was skipped because its start could not be durably recorded",
							beforeErr.Error(),
							"Keep the USB device connected and download diagnostics. Repair persistent logging, then normally reboot Unraid with the device still connected to clear volatile UD operation markers and complete startup recovery; refresh Unassigned Devices before retrying USB Guardian.",
							map[string]any{"identity": rollbackIdentityData(d)},
						)
					} else {
						rollbackCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
						rollbackErr := e.Coordinator.Rollback(rollbackCtx, d, req.JobID)
						cancel()
						if rollbackErr != nil {
							recoveryPending = true
							job.Warnings = append(job.Warnings, "UD operation barrier release failed: "+rollbackErr.Error())
							rollbackReason = &Reason{Code: "rollback_failed", Message: "Unassigned Devices operation barrier could not be released", Detail: rollbackErr.Error(), Advice: "Keep the USB device connected and download diagnostics. Then normally reboot Unraid with the device still connected to clear volatile UD operation markers and complete startup recovery; refresh Unassigned Devices before retrying USB Guardian."}
							if appendErr := journal.Append(Event{Level: "error", Stage: stage, Type: "rollback_failed", Message: rollbackErr.Error(), Data: map[string]any{"identity": rollbackIdentityData(d)}}); appendErr != nil {
								job.Warnings = append(job.Warnings, "durable rollback_failed record failed: "+appendErr.Error())
							}
						} else if appendErr := journal.Append(Event{Level: "info", Stage: stage, Type: "rollback_after", Message: "UD operation barrier released after target identity revalidation", Data: map[string]any{"identity": rollbackIdentityData(d)}}); appendErr != nil {
							job.Warnings = append(job.Warnings, "durable rollback_after record failed: "+appendErr.Error())
						}
					}
				}
			}
		}
		var snapshotErr error
		if d.KernelName != "" {
			_, snapshotErr = journal.WriteSnapshot("failure", e.Capture(e.Config, &d))
		} else {
			_, snapshotErr = journal.WriteSnapshot("failure", e.Capture(e.Config, nil))
		}
		if snapshotErr != nil {
			job.Warnings = append(job.Warnings, "failure diagnostic snapshot could not be persisted: "+snapshotErr.Error())
			_ = journal.Append(Event{Level: "error", Stage: stage, Type: "diagnostic_snapshot_failed", Message: snapshotErr.Error()})
		}
		job.Status, job.Stage, job.Message, job.Error, job.SafeToUnplug = "failed", stage, "safe eject failed", cause.Error(), false
		if strictlyUnmounted && !removed {
			job.Message = "safe eject stopped after ordinary unmount; the USB device remains strictly unmounted. Keep it connected and download diagnostics"
		} else if recoveryPending {
			job.Message = "safe eject failed; Unassigned Devices recovery state was preserved. Keep the USB device connected, download diagnostics, and normally reboot Unraid with it still connected"
		}
		job.Terminal = true
		var safetyErr *SafetyError
		if errors.As(cause, &safetyErr) {
			job.Reasons = safetyErr.Reasons
		} else {
			job.Reasons = []Reason{failureReason(stage, cause, removed, strictlyUnmounted)}
		}
		if rollbackReason != nil {
			job.Reasons = appendReason(job.Reasons, *rollbackReason)
		}
		if strictlyUnmounted && !removed {
			unmountedAdvice := " The device remains strictly unmounted. Keep it connected and download diagnostics."
			if recoveryPending {
				unmountedAdvice += " Then, with the USB device still connected, normally reboot Unraid to clear volatile UD operation markers and complete startup recovery; refresh Unassigned Devices before retrying USB Guardian."
			} else {
				unmountedAdvice += " Because UD Finalize completed, you may normally remount it through Unassigned Devices or retry USB Guardian after resolving the reported check."
			}
			for i := range job.Reasons {
				if !strings.Contains(job.Reasons[i].Advice, "remains strictly unmounted") {
					job.Reasons[i].Advice += unmountedAdvice
				}
			}
		}
		job.FinishedAt = e.Now()
		job.UpdatedAt = job.FinishedAt
		_ = journal.Append(Event{Level: "error", Stage: stage, Type: "transaction_failed", Message: cause.Error(), Data: map[string]any{"removed": removed, "quiesced": quiesced, "finalized": finalized, "rollback_prohibited": rollbackProhibited, "recovery_pending": recoveryPending, "adapter_phase": adapterPhase}})
		writeErr := store.Write(job)
		var finishErr error
		if recoveryPending {
			pendingErr := journal.Append(Event{Level: "error", Stage: "terminal", Type: "failed_recovery_pending", Message: "transaction failed with preserved UD recovery state", Data: map[string]any{"adapter_phase": adapterPhase, "rollback_prohibited": rollbackProhibited}})
			finishErr = errors.Join(pendingErr, journal.Close())
		} else {
			finishErr = journal.Finish("failed", cause.Error())
		}
		return job, errors.Join(cause, writeErr, finishErr)
	}
	setStage := func(stage string, progress int, message string, data map[string]any) error {
		job.Stage, job.Progress, job.Message = stage, progress, message
		job.UpdatedAt = e.Now()
		if err := journal.Append(Event{Level: "info", Stage: stage, Type: "stage", Message: message, Data: data}); err != nil {
			return err
		}
		return store.Write(job)
	}
	if err := setStage("validate", 5, "validating stable device identity", nil); err != nil {
		return fail("validate", err)
	}
	d, err = e.ResolveTarget(e.Config, req.Target)
	if err != nil {
		return fail("validate", err)
	}
	job.Device = &d
	if len(d.Reasons) > 0 {
		return fail("validate", &SafetyError{Reasons: d.Reasons})
	}
	if err := setStage("ud_inspect", 10, "verifying Unassigned Devices compatibility", nil); err != nil {
		return fail("ud_inspect", err)
	}
	if err := e.Coordinator.Inspect(ctx, d, req.JobID); err != nil {
		return fail("ud_inspect", err)
	}
	if _, err := journal.WriteSnapshot("preflight", e.Capture(e.Config, &d)); err != nil {
		return fail("preflight", err)
	}
	if err := setStage("preflight", 20, "checking shfs and all known device users", nil); err != nil {
		return fail("preflight", err)
	}
	preSHFS := e.Health(e.Config)
	if !shfsHealthy(preSHFS) {
		return fail("preflight", fmt.Errorf("shfs_unhealthy: %s", preSHFS.Error))
	}
	if reasons := e.Safety(e.Config, d, true); len(reasons) > 0 {
		return fail("preflight", &SafetyError{Reasons: reasons})
	}
	preflightMounts, err := e.Mounts(e.Config, d.Blocks)
	if err != nil {
		return fail("preflight", fmt.Errorf("inspect active target mount layout: %w", err))
	}
	if reason := unsupportedMountLayoutReason(preflightMounts); reason != nil {
		return fail("preflight", &SafetyError{Reasons: []Reason{*reason}})
	}
	if err := runConfiguredHook(ctx, e.Config.PreUnmountHook, d, req.JobID); err != nil {
		return fail("quiesce", fmt.Errorf("pre-unmount hook: %w", err))
	}
	if err := setStage("quiesce", 30, "stopping new Unassigned Devices access", nil); err != nil {
		return fail("quiesce", err)
	}
	quiesceAttempted = true
	if err := e.Coordinator.Quiesce(ctx, d, req.JobID); err != nil {
		return fail("quiesce", err)
	}
	quiesced = true
	if err := setStage("strict_unmount", 40, "strictly unmounting filesystems", nil); err != nil {
		return fail("strict_unmount", err)
	}
	mounts, err := e.Mounts(e.Config, d.Blocks)
	if err != nil {
		return fail("strict_unmount", err)
	}
	if reason := unsupportedMountLayoutReason(mounts); reason != nil {
		return fail("strict_unmount", &SafetyError{Reasons: []Reason{*reason}})
	}
	for _, mount := range mounts {
		if !mountAllowed(e.Config, mount.MountPoint) {
			return fail("strict_unmount", fmt.Errorf("mount point is outside approved roots: %s", mount.MountPoint))
		}
		if err := e.Ops.Unmount(mount.MountPoint); err != nil {
			return fail("strict_unmount", fmt.Errorf("ordinary unmount %s: %w", mount.MountPoint, err))
		}
		_ = journal.Append(Event{Level: "info", Stage: "strict_unmount", Type: "unmounted", Message: "ordinary unmount completed", Data: map[string]any{"mount_point": mount.MountPoint, "major_minor": mount.MajorMinor}})
	}
	strictlyUnmounted, rollbackProhibited = true, true
	if err := setStage("ud_finalize", 45, "finalizing Unassigned Devices immediately after ordinary unmount", nil); err != nil {
		return fail("finalize", err)
	}
	if err := e.Coordinator.Finalize(ctx, d, req.JobID); err != nil {
		return fail("finalize", err)
	}
	finalized = true
	if err := runConfiguredHook(ctx, e.Config.PostUnmountHook, d, req.JobID); err != nil {
		return fail("finalize", fmt.Errorf("post-unmount hook: %w", err))
	}
	if err := setStage("verify_idle", 50, "verifying all mount namespaces and process references are clear", nil); err != nil {
		return fail("verify_idle", err)
	}
	if reasons := e.Safety(e.Config, d, false); len(reasons) > 0 {
		return fail("verify_idle", &SafetyError{Reasons: reasons})
	}
	fresh, err := e.ResolveTarget(e.Config, req.Target)
	if err != nil {
		return fail("verify_idle", fmt.Errorf("identity revalidation failed: %w", err))
	}
	d = fresh
	job.Device = &d
	if err := setStage("pre_remove_shfs", 55, "confirming shfs is stable after strict unmount", nil); err != nil {
		return fail("pre_remove_shfs", err)
	}
	if err := checkSHFSWindow(ctx, e.Config.SHFSHealthSeconds, shfsPIDSet(preSHFS), e.Config, e.Health); err != nil {
		return fail("pre_remove_shfs", err)
	}
	if _, err := journal.WriteSnapshot("pre_remove", e.Capture(e.Config, &d)); err != nil {
		return fail("pre_remove", err)
	}
	if err := setStage("post_finalize_shfs", 59, "rechecking shfs after Unassigned Devices finalization", nil); err != nil {
		return fail("post_finalize_shfs", err)
	}
	if err := checkSHFSWindow(ctx, 0, shfsPIDSet(preSHFS), e.Config, e.Health); err != nil {
		return fail("post_finalize_shfs", err)
	}
	if err := setStage("post_finalize_idle", 59, "checking for access recreated by finalization hooks", nil); err != nil {
		return fail("post_finalize_idle", err)
	}
	if reasons := e.PostFinalizeSafety(e.Config, d); len(reasons) > 0 {
		return fail("post_finalize_idle", &SafetyError{Reasons: reasons})
	}
	if err := setStage("exclusive_open", 60, "acquiring exclusive block-device handles", nil); err != nil {
		return fail("exclusive_open", err)
	}
	var roots []string
	for _, b := range d.Blocks {
		if !b.Partition {
			roots = append(roots, b.DevNode)
		}
	}
	if len(roots) == 0 {
		return fail("exclusive_open", errors.New("no top-level block device found"))
	}
	sort.Strings(roots)
	handles, err = e.Ops.OpenExclusive(roots)
	if err != nil {
		return fail("exclusive_open", err)
	}
	defer func() { _ = closeHandles(handles) }()
	if err := setStage("flush", 68, "flushing filesystem and device caches", nil); err != nil {
		return fail("flush", err)
	}
	for _, h := range handles {
		if err := h.Sync(); err != nil {
			return fail("flush", fmt.Errorf("fsync %s: %w", h.Name(), err))
		}
		_ = journal.Append(Event{Level: "info", Stage: "flush", Type: "block_fsync", Message: "block device fsync completed", Data: map[string]any{"device": h.Name()}})
		if e.Config.EnableSGIO {
			if err := h.SCSISync(); err != nil {
				warning := "SCSI SYNCHRONIZE CACHE unsupported/failed for " + h.Name() + ": " + err.Error()
				job.Warnings = append(job.Warnings, warning)
				_ = journal.Append(Event{Level: "warning", Stage: "flush", Type: "sg_sync_warning", Message: warning})
			}
			if err := h.SCSIStop(); err != nil {
				warning := "SCSI START STOP UNIT unsupported/failed for " + h.Name() + ": " + err.Error()
				job.Warnings = append(job.Warnings, warning)
				_ = journal.Append(Event{Level: "warning", Stage: "flush", Type: "sg_stop_warning", Message: warning})
			}
		}
	}
	if err := setStage("final_idle", 71, "performing the final process, namespace, swap, and holder scan", nil); err != nil {
		return fail("final_idle", err)
	}
	if reasons := e.FinalSafety(e.Config, d, handles); len(reasons) > 0 {
		return fail("final_idle", &SafetyError{Reasons: reasons})
	}
	if err := setStage("final_identity", 72, "revalidating block and USB identity from exclusive handles", nil); err != nil {
		return fail("final_identity", err)
	}
	if err := e.VerifyIdentity(e.Config, req.Target, d, handles); err != nil {
		return fail("final_identity", err)
	}
	_ = journal.Append(Event{Level: "info", Stage: "final_identity", Type: "identity_verified", Message: "diskseq, USB identity, and exclusive handle device numbers match"})
	if err := setStage("usb_remove", 75, "logically removing the physical USB device", nil); err != nil {
		return fail("usb_remove", err)
	}
	var eventCount atomic.Int32
	var monitorErr error
	stopUEvent, monitorErr = e.Ops.StartUEventMonitor(func(event map[string]string) {
		if eventCount.Add(1) > 512 {
			return
		}
		_ = journal.Append(Event{Level: "info", Stage: "usb_remove", Type: "kernel_uevent", Message: event["ACTION"] + " " + event["DEVPATH"], Data: map[string]any{"uevent": event}})
	})
	if monitorErr != nil {
		job.Warnings = append(job.Warnings, "kernel uevent monitor unavailable: "+monitorErr.Error())
		_ = journal.Append(Event{Level: "warning", Stage: "usb_remove", Type: "uevent_monitor_warning", Message: monitorErr.Error()})
	}
	if stopUEvent != nil {
		defer func() {
			if stopUEvent != nil {
				stopUEvent()
			}
		}()
	}
	removePath := filepath.Join(e.Config.SysRoot, filepath.FromSlash(d.USBPath), "remove")
	if err := e.Ops.WriteUSBRemove(removePath); err != nil {
		return fail("usb_remove", err)
	}
	removed = true
	_ = journal.Append(Event{Level: "info", Stage: "usb_remove", Type: "usb_remove_written", Message: "physical USB remove control accepted", Data: map[string]any{"path": removePath}})
	if err := closeHandles(handles); err != nil {
		job.Warnings = append(job.Warnings, "close exclusive handles: "+err.Error())
	}
	handles = nil
	if err := setStage("settle", 85, "waiting for block, udev, and USB nodes to disappear", nil); err != nil {
		return fail("settle", err)
	}
	if err := e.WaitRemoved(e.Config, d, time.Duration(e.Config.SettleSeconds)*time.Second); err != nil {
		return fail("settle", err)
	}
	if stopUEvent != nil {
		stopUEvent()
		stopUEvent = nil
	}
	if _, err := journal.WriteSnapshot("post_remove", e.Capture(e.Config, &d)); err != nil {
		return fail("post_remove", err)
	}
	if err := setStage("shfs_health", 94, "confirming shfs remains stable", nil); err != nil {
		return fail("shfs_health", err)
	}
	if err := checkSHFSWindow(ctx, e.Config.SHFSHealthSeconds, shfsPIDSet(preSHFS), e.Config, e.Health); err != nil {
		return fail("shfs_health", err)
	}
	if _, err := journal.WriteSnapshot("shfs", e.Capture(e.Config, &d)); err != nil {
		return fail("shfs_health", err)
	}
	job.Status, job.Stage, job.Progress, job.Message, job.SafeToUnplug = "completed", "safe_to_unplug", 100, "USB device is safely removed and can now be unplugged", true
	job.Terminal = true
	job.FinishedAt = e.Now()
	job.UpdatedAt = job.FinishedAt
	if err := store.Write(job); err != nil {
		return fail("terminal", err)
	}
	if err := journal.Finish("safe_to_unplug", job.Message); err != nil {
		return job, err
	}
	return job, nil
}

func validateRollbackIdentity(target string, expected, current Device) error {
	if target == "" {
		return errors.New("rollback target token is empty")
	}
	if expected.Token != target || current.Token != target {
		return errors.New("rollback device identity does not carry the exact requested target token")
	}
	type identityField struct {
		name     string
		expected string
		current  string
		required bool
	}
	fields := []identityField{
		{name: "kernel_name", expected: expected.KernelName, current: current.KernelName, required: true},
		{name: "major_minor", expected: expected.MajorMinor, current: current.MajorMinor, required: true},
		{name: "diskseq", expected: expected.DiskSeq, current: current.DiskSeq, required: true},
		{name: "usb_path", expected: expected.USBPath, current: current.USBPath, required: true},
		{name: "serial", expected: expected.Serial, current: current.Serial},
		{name: "usb_vid", expected: expected.USBVID, current: current.USBVID},
		{name: "usb_pid", expected: expected.USBPID, current: current.USBPID},
		{name: "usb_serial", expected: expected.USBSerial, current: current.USBSerial},
		{name: "usb_busnum", expected: expected.USBBusNum, current: current.USBBusNum},
		{name: "usb_devnum", expected: expected.USBDevNum, current: current.USBDevNum},
	}
	for _, field := range fields {
		if field.required && (field.expected == "" || field.current == "") {
			return fmt.Errorf("rollback identity field %s is missing", field.name)
		}
		if field.expected != field.current {
			return fmt.Errorf("rollback identity field %s changed: expected %q, current %q", field.name, field.expected, field.current)
		}
	}
	expectedRoots := rollbackRootIdentity(expected)
	currentRoots := rollbackRootIdentity(current)
	if len(expectedRoots) == 0 || len(currentRoots) != len(expectedRoots) {
		return fmt.Errorf("rollback top-level block set changed: expected %d roots, current %d", len(expectedRoots), len(currentRoots))
	}
	for name, identity := range expectedRoots {
		if currentRoots[name] != identity {
			return fmt.Errorf("rollback top-level block identity changed for %s", name)
		}
	}
	return nil
}

func rollbackRootIdentity(d Device) map[string]string {
	roots := make(map[string]string)
	for _, block := range d.Blocks {
		if !block.Partition {
			roots[block.Name] = block.MajorMinor + "\x00" + block.DiskSeq
		}
	}
	return roots
}

func rollbackIdentityData(d Device) map[string]any {
	return map[string]any{
		"kernel_name": d.KernelName,
		"major_minor": d.MajorMinor,
		"diskseq":     d.DiskSeq,
		"usb_path":    d.USBPath,
		"usb_serial":  d.USBSerial,
		"usb_busnum":  d.USBBusNum,
		"usb_devnum":  d.USBDevNum,
	}
}

func finalSafetyReasons(cfg Config, d Device, handles []ExclusiveHandle) []Reason {
	reasons := transactionSafetyReasons(cfg, d)
	owned := make(map[string]bool)
	for _, handle := range handles {
		owned[handle.Name()] = true
	}
	out := make([]Reason, 0, len(reasons))
	for _, reason := range reasons {
		if len(reason.Blockers) == 0 {
			out = append(out, reason)
			continue
		}
		allOwned := true
		for _, blocker := range reason.Blockers {
			if blocker.PID != os.Getpid() || blocker.Kind != "fd" || !owned[blocker.Path] {
				allOwned = false
				break
			}
		}
		if !allOwned {
			out = append(out, reason)
		}
	}
	return out
}

func transactionSafetyReasons(cfg Config, d Device) []Reason {
	reasons := staticProtectionReasons(cfg, d)
	for _, reason := range dynamicSafetyReasons(cfg, d, false) {
		reasons = appendReason(reasons, reason)
	}
	return reasons
}

func failureReason(stage string, cause error, removed, strictlyUnmounted bool) Reason {
	detail := cause.Error()
	unmounted := " The device remains strictly unmounted. Keep it connected and download diagnostics before normally remounting it through Unassigned Devices or retrying USB Guardian."
	if !strictlyUnmounted || removed {
		unmounted = ""
	}
	var adapterErr *UDAdapterError
	if errors.As(cause, &adapterErr) && adapterErr.IsIrreversible() {
		return Reason{
			Code:    "ud_state_unsafe",
			Message: "Unassigned Devices crossed the irreversible finalization boundary",
			Detail:  detail,
			Advice:  "The device remains strictly unmounted. Keep the USB device connected and download diagnostics. Then normally reboot Unraid with the device still connected to clear volatile UD operation markers and complete startup recovery; refresh Unassigned Devices before retrying USB Guardian.",
		}
	}
	switch stage {
	case "strict_unmount":
		return Reason{Code: "mounted_busy", Message: "ordinary unmount did not complete", Detail: detail, Advice: "Close open files and disconnect SMB/NFS clients shown in diagnostics, stop affected containers or VMs through their normal managers, then retry. Never use force or lazy unmount."}
	case "exclusive_open":
		return Reason{Code: "open_files", Message: "the top-level block device could not be opened exclusively", Detail: detail, Advice: "Stop the VM, container, preclear task, or storage tool holding the block device through its normal controls, then retry." + unmounted}
	case "preflight", "pre_remove_shfs", "post_finalize_shfs", "shfs_health":
		return Reason{Code: "shfs_unhealthy", Message: "shfs or /mnt/user failed a safety health check", Detail: detail, Advice: "Do not unplug the USB device. Download diagnostics and restore stable /mnt/user access before retrying."}
	case "ud_inspect":
		return udInspectionReason(cause)
	case "quiesce":
		return Reason{Code: "mounted_busy", Message: "Unassigned Devices access could not be quiesced", Detail: detail, Advice: "Disconnect share clients and close open files through their normal applications, then retry."}
	case "verify_idle":
		return Reason{Code: "inspection_failed", Message: "post-unmount idle verification failed", Detail: detail, Advice: "Leave the device connected, review the transaction diagnostics, resolve every listed holder, and retry."}
	case "final_identity", "validate":
		return Reason{Code: "inspection_failed", Message: "the block or USB identity changed during the transaction", Detail: detail, Advice: "Leave the device connected, refresh the device list, and start a new safe-eject transaction." + unmounted}
	case "flush":
		return Reason{Code: "flush_failed", Message: "device data could not be flushed safely", Detail: detail, Advice: "Do not unplug the device. Stop writers normally, review diagnostics, and retry." + unmounted}
	case "usb_remove":
		return Reason{Code: "usb_remove_failed", Message: "the physical USB remove control failed", Detail: detail, Advice: "Leave the device connected and download diagnostics; do not physically unplug it." + unmounted}
	case "settle":
		return Reason{Code: "remove_incomplete", Message: "USB removal did not reach a fully settled state", Detail: detail, Advice: "Do not unplug until diagnostics confirm all block, udev, and USB nodes are gone."}
	case "finalize":
		advice := "Keep the USB device connected, review diagnostics, and refresh Unassigned Devices before retrying."
		if removed {
			advice = "The kernel removal completed but final verification did not. Download diagnostics and do not reconnect the device until the failure is reviewed."
		}
		return Reason{Code: "finalize_failed", Message: "Unassigned Devices finalization failed", Detail: detail, Advice: advice}
	default:
		return Reason{Code: "inspection_failed", Message: "safe-eject transaction stopped before completion", Detail: detail, Advice: "Leave the device connected and review the diagnostic bundle before retrying."}
	}
}

func checkSHFSWindow(ctx context.Context, seconds int, expectedPIDs []int, cfg Config, healthFn func(Config) SHFSHealth) error {
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for {
		health := healthFn(cfg)
		observedPIDs := shfsPIDSet(health)
		if !shfsHealthy(health) || !equalIntSets(observedPIDs, expectedPIDs) {
			return fmt.Errorf("shfs_unhealthy: expected pids=%v, observed pids=%v, states=%v, error=%s", expectedPIDs, observedPIDs, health.ProcessStates, health.Error)
		}
		if seconds <= 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return nil
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func equalIntSets(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type SafetyError struct{ Reasons []Reason }

func (s *SafetyError) Error() string {
	parts := make([]string, 0, len(s.Reasons))
	for _, r := range s.Reasons {
		if r.Detail != "" {
			parts = append(parts, r.Code+": "+r.Message+" ("+r.Detail+")")
		} else {
			parts = append(parts, r.Code+": "+r.Message)
		}
	}
	return strings.Join(parts, "; ")
}

func dynamicSafetyReasons(cfg Config, d Device, allowSelfMounts bool) []Reason {
	scan := ScanUsage(cfg, d, allowSelfMounts)
	liveMounts, _ := targetMounts(cfg, d.Blocks)
	var out []Reason
	if len(scan.Errors) > 0 {
		out = append(out, Reason{Code: "inspection_failed", Message: "not every process and mount namespace could be inspected", Detail: strings.Join(scan.Errors, "; "), Advice: "Review the diagnostic bundle and restore full root visibility of /proc before retrying."})
	}
	for _, ref := range scan.References {
		if allowSelfMounts && expectedFuseDaemonReference(ref, liveMounts, d.Blocks) {
			continue
		}
		code, message, advice := "mounted_busy", "the device is still referenced", "Close the application or unmount the dependent resource normally, then retry."
		name := strings.ToLower(ref.Process)
		switch {
		case ref.Kind == "swap":
			code, message, advice = "swap_active", "the device is active swap", "Disable this swap through its normal configuration, verify /proc/swaps, then retry."
		case ref.Kind == "block_holder":
			code, message, advice = "holder_active", "a block holder is still active", "Deactivate the mapped volume, RAID member, or pool through its owning tool, then retry."
		case strings.Contains(name, "qemu") || strings.Contains(name, "libvirt"):
			code, message, advice = "vm_passthrough", "a virtual machine is using the device", "Shut down the VM or remove its USB/block assignment through VM Manager, then retry."
		case strings.Contains(name, "docker") || strings.Contains(name, "containerd") || processInContainer(cfg, ref.PID):
			code, message, advice = "docker_bind", "a container mount namespace is using the device", "Stop the affected container through Docker Manager and retry."
		case strings.Contains(name, "smb") || strings.Contains(name, "nfs"):
			code, message, advice = "smb_nfs_client", "an SMB or NFS process is using the device", "Disconnect clients and stop the corresponding share through Unassigned Devices, then retry."
		case ref.Kind == "fd" || ref.Kind == "cwd" || ref.Kind == "root" || ref.Kind == "map_files":
			code, message, advice = "open_files", "a process has an open reference on the device", "Close the named process or file through its normal application controls, then retry."
		}
		if referenceTouchesSibling(ref, d) {
			code, message, advice = "sibling_busy", "another disk or partition in the same physical USB device is busy", "Close or normally unmount every sibling device in the USB enclosure, then retry."
		}
		out = appendReason(out, Reason{Code: code, Message: message, Detail: fmt.Sprintf("pid=%d process=%s kind=%s path=%s", ref.PID, ref.Process, ref.Kind, ref.Path), Advice: advice, Blockers: []Reference{ref}})
	}
	if reason := unsupportedFilesystemReason(cfg, d); reason != nil {
		out = appendReason(out, *reason)
	}
	if refs := preclearReferences(cfg, d); len(refs) > 0 {
		out = appendReason(out, Reason{Code: "preclear_running", Message: "a preclear operation targets this device", Advice: "Stop or finish preclear through the Preclear plugin, then retry.", Blockers: refs})
	}
	return out
}

func expectedFuseDaemonReference(ref Reference, mounts []Mount, blocks []BlockDevice) bool {
	if ref.Kind != "fd" {
		return false
	}
	name := strings.ToLower(ref.Process)
	known := strings.Contains(name, "ntfs-3g") || strings.Contains(name, "mount.ntfs") || strings.Contains(name, "exfat-fuse") || strings.Contains(name, "mount.exfat") || strings.Contains(name, "fuse2fs") || strings.Contains(name, "fuseiso")
	if !known {
		return false
	}
	pathMatches := false
	for _, block := range blocks {
		if ref.Path == block.DevNode {
			pathMatches = true
			break
		}
	}
	if !pathMatches {
		return false
	}
	for _, mount := range mounts {
		if strings.HasPrefix(strings.ToLower(mount.FSType), "fuse") && mountSourceMatches(mount.Source, blocks) {
			return true
		}
	}
	return false
}

func referenceTouchesSibling(ref Reference, d Device) bool {
	for _, b := range d.Blocks {
		if b.Name == d.KernelName || (b.Partition && strings.HasPrefix(b.Name, d.KernelName)) {
			continue
		}
		if ref.Detail == b.MajorMinor || ref.Path == b.DevNode || strings.Contains(ref.Detail, b.Name) {
			return true
		}
	}
	return false
}

func processInContainer(cfg Config, pid int) bool {
	if pid <= 0 {
		return false
	}
	text := strings.ToLower(readTrim(filepath.Join(cfg.ProcRoot, fmt.Sprint(pid), "cgroup")))
	return strings.Contains(text, "docker") || strings.Contains(text, "containerd") || strings.Contains(text, "kubepods")
}

func unsupportedFilesystemReason(cfg Config, d Device) *Reason {
	bad := map[string]bool{"crypto_luks": true, "zfs_member": true, "linux_raid_member": true, "lvm2_member": true}
	allowed := map[string]bool{"": true, "xfs": true, "btrfs": true, "ext2": true, "ext3": true, "ext4": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "udf": true, "iso9660": true, "hfs": true, "hfsplus": true}
	for _, b := range d.Blocks {
		udevPath := filepath.Join(cfg.RunRoot, "udev", "data", "b"+b.MajorMinor)
		data := readTrim(udevPath)
		if data == "" && filepath.Clean(cfg.SysRoot) == filepath.Clean("/sys") {
			return &Reason{Code: "inspection_failed", Message: "udev metadata is unavailable for a target block device", Detail: b.Name + " " + udevPath, Advice: "Wait for udev and Unassigned Devices discovery to finish, then retry."}
		}
		for _, line := range strings.Split(data, "\n") {
			line = strings.TrimPrefix(line, "E:")
			if k, v, ok := strings.Cut(line, "="); ok && k == "ID_FS_TYPE" && bad[strings.ToLower(v)] {
				return &Reason{Code: "unsupported_filesystem", Message: "encrypted, ZFS, RAID, and LVM member devices are not handled automatically", Detail: b.Name + " type=" + v, Advice: "Export, close, or deactivate it with its owning storage tool before using safe eject."}
			} else if ok && k == "ID_FS_TYPE" && !allowed[strings.ToLower(v)] {
				return &Reason{Code: "unsupported_filesystem", Message: "the detected filesystem or member type is not approved for automatic safe eject", Detail: b.Name + " type=" + v, Advice: "Unmount or export it with its owning storage tool and review diagnostics before retrying."}
			}
		}
	}
	return nil
}

func preclearReferences(cfg Config, d Device) []Reference {
	dirs, _ := os.ReadDir(cfg.ProcRoot)
	var out []Reference
	for _, dir := range dirs {
		if _, err := fmt.Sscanf(dir.Name(), "%d", new(int)); err != nil {
			continue
		}
		cmdline, _ := os.ReadFile(filepath.Join(cfg.ProcRoot, dir.Name(), "cmdline"))
		text := strings.ReplaceAll(string(cmdline), "\x00", " ")
		if !strings.Contains(strings.ToLower(text), "preclear") {
			continue
		}
		for _, b := range d.Blocks {
			if strings.Contains(text, b.DevNode) || strings.Contains(text, b.Name) {
				out = append(out, Reference{PID: parseInt(dir.Name()), Process: "preclear", Kind: "preclear", Path: b.DevNode})
				break
			}
		}
	}
	return out
}

func mountAllowed(cfg Config, mountpoint string) bool {
	for _, prefix := range cfg.AllowedMountPrefixes {
		if pathWithin(mountpoint, strings.TrimSuffix(prefix, "/")) {
			return true
		}
	}
	return false
}

func runConfiguredHook(ctx context.Context, command []string, d Device, jobID string) error {
	if len(command) == 0 {
		return nil
	}
	return runCommand(ctx, command, d.KernelName, jobID)
}
