package guardian

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeHandle struct {
	name       string
	majorMinor string
	syncErr    error
	closed     bool
}

func (h *fakeHandle) Name() string                { return h.name }
func (h *fakeHandle) MajorMinor() (string, error) { return h.majorMinor, nil }
func (h *fakeHandle) Sync() error                 { return h.syncErr }
func (h *fakeHandle) SCSISync() error             { return nil }
func (h *fakeHandle) SCSIStop() error             { return nil }
func (h *fakeHandle) Close() error                { h.closed = true; return nil }

type fakeOps struct {
	unmountErr error
	removeErr  error
	unmounted  []string
	removed    bool
	opened     []string
}

func (f *fakeOps) Unmount(path string) error {
	f.unmounted = append(f.unmounted, path)
	return f.unmountErr
}
func (f *fakeOps) OpenExclusive(paths []string) ([]ExclusiveHandle, error) {
	f.opened = append(f.opened, paths...)
	var out []ExclusiveHandle
	for _, p := range paths {
		out = append(out, &fakeHandle{name: p, majorMinor: "8:240"})
	}
	return out, nil
}
func (f *fakeOps) WriteUSBRemove(string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removed = true
	return nil
}
func (f *fakeOps) StartUEventMonitor(cb func(map[string]string)) (func(), error) {
	cb(map[string]string{"ACTION": "remove", "DEVPATH": "/devices/test"})
	return func() {}, nil
}

type fakeCoordinator struct {
	inspect, quiesce, finalize, rollback int
	inspectErr, quiesceErr, finalizeErr  error
	onFinalize                           func()
}

func (f *fakeCoordinator) Inspect(context.Context, Device, string) error {
	f.inspect++
	return f.inspectErr
}
func (f *fakeCoordinator) Quiesce(context.Context, Device, string) error {
	f.quiesce++
	return f.quiesceErr
}
func (f *fakeCoordinator) Finalize(context.Context, Device, string) error {
	f.finalize++
	if f.onFinalize != nil {
		f.onFinalize()
	}
	return f.finalizeErr
}
func (f *fakeCoordinator) Rollback(context.Context, Device, string) error { f.rollback++; return nil }

func testEjector(t *testing.T, ops *fakeOps, coordinator *fakeCoordinator, device Device) (Ejector, EjectRequest) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.SHFSHealthSeconds = 0
	cfg.EnableSGIO = false
	req := EjectRequest{Target: "opaque", JobID: "job-test", JobDir: filepath.Join(t.TempDir(), "jobs"), LogDir: filepath.Join(t.TempDir(), "logs")}
	health := SHFSHealth{PathAccessible: true, MountVerified: true, PID: 123, ProcessState: "S (sleeping)"}
	e := Ejector{
		Config: cfg, Ops: ops, Coordinator: coordinator,
		ResolveTarget: func(Config, string) (Device, error) { return device, nil },
		Capture: func(Config, *Device) DiagnosticSnapshot {
			return DiagnosticSnapshot{SchemaVersion: SchemaVersion, CapturedAt: time.Now().UTC(), SHFS: health}
		},
		Health:             func(Config) SHFSHealth { return health },
		Safety:             func(Config, Device, bool) []Reason { return nil },
		Mounts:             func(Config, []BlockDevice) ([]Mount, error) { return nil, nil },
		WaitRemoved:        func(Config, Device, time.Duration) error { return nil },
		VerifyIdentity:     func(Config, string, Device, []ExclusiveHandle) error { return nil },
		FinalSafety:        func(Config, Device, []ExclusiveHandle) []Reason { return nil },
		PostFinalizeSafety: func(Config, Device) []Reason { return nil },
	}
	return e, req
}

func ejectDevice() Device {
	return Device{SchemaVersion: SchemaVersion, Token: "opaque", DevX: "/dev/sdz", KernelName: "sdz", MajorMinor: "8:240", DiskSeq: "8", USBPath: "devices/usb1/1-1", Eligible: true, Blocks: []BlockDevice{{Name: "sdz", DevNode: "/dev/sdz", MajorMinor: "8:240"}}}
}

func TestEjectTransactionSuccess(t *testing.T) {
	ops, coordinator := &fakeOps{}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	job, err := e.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !job.Terminal || !job.SafeToUnplug || job.Status != "completed" || job.Progress != 100 {
		t.Fatalf("unexpected completed job: %+v", job)
	}
	if !ops.removed || coordinator.inspect != 1 || coordinator.quiesce != 1 || coordinator.finalize != 1 || coordinator.rollback != 0 {
		t.Fatalf("wrong operation sequence: ops=%+v coordinator=%+v", ops, coordinator)
	}
	if fileExists(filepath.Join(req.LogDir, "transactions", req.JobID, "active.json")) {
		t.Fatal("active marker remained after completion")
	}
	b, err := os.ReadFile(filepath.Join(req.LogDir, "transactions", req.JobID, "timeline.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"preflight", "pre_remove", "usb_remove_written", "post_remove", "safe_to_unplug"} {
		if !strings.Contains(string(b), stage) {
			t.Fatalf("timeline lacks %q: %s", stage, b)
		}
	}
}

func TestBusyReferenceStopsBeforeQuiesceAndRemove(t *testing.T) {
	ops, coordinator := &fakeOps{}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	e.Safety = func(Config, Device, bool) []Reason {
		return []Reason{{Code: "open_files", Message: "busy", Advice: "close normally"}}
	}
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("busy device should fail")
	}
	if !job.Terminal || job.SafeToUnplug || ops.removed || coordinator.quiesce != 0 || coordinator.rollback != 0 {
		t.Fatalf("unsafe busy handling: job=%+v ops=%+v coordinator=%+v", job, ops, coordinator)
	}
}

func TestUnmountFailureRollsBackWithoutRemove(t *testing.T) {
	ops, coordinator := &fakeOps{unmountErr: errors.New("busy")}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	e.Mounts = func(Config, []BlockDevice) ([]Mount, error) {
		return []Mount{{MountPoint: "/mnt/disks/usb", MajorMinor: "8:240"}}, nil
	}
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("unmount failure should fail")
	}
	if job.SafeToUnplug || ops.removed || coordinator.quiesce != 1 || coordinator.rollback != 1 {
		t.Fatalf("wrong rollback behavior: job=%+v ops=%+v coordinator=%+v", job, ops, coordinator)
	}
	if r := findReason(job.Reasons, "mounted_busy"); r == nil || r.Advice == "" {
		t.Fatalf("unmount failure lacks structured advice: %#v", job.Reasons)
	}
	timeline, readErr := os.ReadFile(filepath.Join(req.LogDir, "transactions", req.JobID, "timeline.jsonl"))
	if readErr != nil || !strings.Contains(string(timeline), "rollback_before") || !strings.Contains(string(timeline), "rollback_after") {
		t.Fatalf("trusted rollback boundary was not durably recorded: err=%v timeline=%s", readErr, timeline)
	}
}

func TestPostRemoveSHFSFailureNeverReportsSafe(t *testing.T) {
	ops, coordinator := &fakeOps{}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	calls := 0
	e.Health = func(Config) SHFSHealth {
		calls++
		if calls <= 3 {
			return SHFSHealth{PathAccessible: true, MountVerified: true, PID: 123, ProcessState: "S"}
		}
		return SHFSHealth{PathAccessible: false, PID: 0, Error: "shfs exited"}
	}
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("post-remove shfs failure should fail")
	}
	if !ops.removed || job.SafeToUnplug || !job.Terminal || job.Stage != "shfs_health" {
		t.Fatalf("incorrect post-remove failure: %+v", job)
	}
	if coordinator.rollback != 0 {
		t.Fatal("must not rollback after physical USB remove")
	}
	if r := findReason(job.Reasons, "shfs_unhealthy"); r == nil || r.Advice == "" {
		t.Fatalf("shfs failure lacks structured advice: %#v", job.Reasons)
	}
}

func TestPostUnmountSHFSFailureStopsBeforeRemove(t *testing.T) {
	ops, coordinator := &fakeOps{}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	calls := 0
	e.Health = func(Config) SHFSHealth {
		calls++
		if calls == 1 {
			return SHFSHealth{PathAccessible: true, MountVerified: true, PID: 123, ProcessState: "S"}
		}
		return SHFSHealth{PathAccessible: false, PID: 0, Error: "shfs exited during unmount"}
	}
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("post-unmount shfs failure should fail")
	}
	if ops.removed || job.SafeToUnplug || !job.Terminal || job.Stage != "pre_remove_shfs" {
		t.Fatalf("unsafe pre-remove gate: %+v", job)
	}
	if coordinator.quiesce != 1 || coordinator.finalize != 1 || coordinator.rollback != 0 {
		t.Fatalf("failure after ordinary unmount must keep finalized UD state: %+v", coordinator)
	}
}

func TestFinalIdentityFailureStopsBeforeRemove(t *testing.T) {
	ops, coordinator := &fakeOps{}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	e.VerifyIdentity = func(Config, string, Device, []ExclusiveHandle) error { return errors.New("diskseq changed") }
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("identity change should fail")
	}
	if ops.removed || job.SafeToUnplug || job.Stage != "final_identity" {
		t.Fatalf("identity failure crossed remove boundary: %+v", job)
	}
	if coordinator.rollback != 0 {
		t.Fatalf("identity failure after finalize must not recreate deleted UD state: %+v", coordinator)
	}
	if r := findReason(job.Reasons, "inspection_failed"); r == nil || r.Advice == "" {
		t.Fatalf("identity failure lacks structured advice: %#v", job.Reasons)
	} else if !strings.Contains(r.Advice, "remains strictly unmounted") {
		t.Fatalf("post-finalize failure does not explain unmounted state: %#v", job.Reasons)
	}
}

func TestQuiesceErrorAlwaysRollsBack(t *testing.T) {
	ops := &fakeOps{}
	coordinator := &fakeCoordinator{quiesceErr: errors.New("adapter timed out")}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("quiesce error should fail")
	}
	if ops.removed || coordinator.rollback != 1 || job.Stage != "quiesce" {
		t.Fatalf("quiesce failure was not rolled back: job=%+v coordinator=%+v", job, coordinator)
	}
}

func TestFinalizeRunsBeforeUSBRemoveAndFailureBlocksRemove(t *testing.T) {
	ops := &fakeOps{}
	sawRemoved := false
	safetyCalls := 0
	sawOrdinaryUnmount := false
	finalizedBeforePostUnmountChecks := false
	coordinator := &fakeCoordinator{finalizeErr: errors.New("REMOVE hook failed"), onFinalize: func() {
		sawRemoved = ops.removed
		sawOrdinaryUnmount = len(ops.unmounted) == 1
		finalizedBeforePostUnmountChecks = safetyCalls == 1
	}}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	e.Safety = func(Config, Device, bool) []Reason {
		safetyCalls++
		return nil
	}
	e.Mounts = func(Config, []BlockDevice) ([]Mount, error) {
		return []Mount{{MountPoint: "/mnt/disks/usb", MajorMinor: "8:240"}}, nil
	}
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("finalize error should fail")
	}
	if sawRemoved || !sawOrdinaryUnmount || !finalizedBeforePostUnmountChecks || ops.removed || coordinator.rollback != 0 || job.Stage != "finalize" {
		t.Fatalf("finalize crossed destructive boundary: job=%+v ops=%+v coordinator=%+v", job, ops, coordinator)
	}
	if !strings.Contains(job.Message, "strictly unmounted") || !strings.Contains(job.Message, "download diagnostics") {
		t.Fatalf("finalize failure did not expose the strict-unmount boundary: %+v", job)
	}
	if !fileExists(filepath.Join(req.LogDir, "transactions", req.JobID, "active.json")) {
		t.Fatal("finalize failure did not preserve its recovery marker")
	}
}

func TestFinalizeHealthRegressionStopsBeforeRemove(t *testing.T) {
	ops, coordinator := &fakeOps{}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	calls := 0
	e.Health = func(Config) SHFSHealth {
		calls++
		if calls <= 2 {
			return SHFSHealth{PathAccessible: true, MountVerified: true, PID: 123, ProcessState: "S"}
		}
		return SHFSHealth{PathAccessible: false, PID: 0, Error: "REMOVE hook destabilized shfs"}
	}
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("post-finalize shfs failure should fail")
	}
	if ops.removed || job.SafeToUnplug || job.Stage != "post_finalize_shfs" {
		t.Fatalf("post-finalize health gate crossed remove: %+v", job)
	}
	if coordinator.finalize != 1 || coordinator.rollback != 0 {
		t.Fatalf("finalized UD state must not be rolled back: %+v", coordinator)
	}
	if r := findReason(job.Reasons, "shfs_unhealthy"); r == nil || r.Advice == "" {
		t.Fatalf("missing shfs advice: %#v", job.Reasons)
	}
}

func TestFinalizeCannotRecreateBusyState(t *testing.T) {
	ops, coordinator := &fakeOps{}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	e.PostFinalizeSafety = func(Config, Device) []Reason {
		return []Reason{{Code: "vm_passthrough", Message: "hook opened raw USB", Advice: "stop VM normally"}}
	}
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("busy state recreated by finalize should fail")
	}
	if ops.removed || len(ops.opened) != 0 || job.Stage != "post_finalize_idle" || coordinator.rollback != 0 {
		t.Fatalf("post-finalize scan crossed boundary: job=%+v ops=%+v", job, ops)
	}
}

func TestFinalSafetyScanStopsBeforeIdentityAndRemove(t *testing.T) {
	ops, coordinator := &fakeOps{}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	e.FinalSafety = func(Config, Device, []ExclusiveHandle) []Reason {
		return []Reason{{Code: "open_files", Message: "late raw fd", Advice: "close normally"}}
	}
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("late busy reference should fail")
	}
	if ops.removed || job.Stage != "final_idle" || coordinator.rollback != 0 {
		t.Fatalf("final safety scan crossed remove: %+v", job)
	}
}

func TestRollbackIdentityChangeSkipsCoordinatorAndPreservesState(t *testing.T) {
	ops, coordinator := &fakeOps{unmountErr: errors.New("busy")}, &fakeCoordinator{}
	expected := ejectDevice()
	e, req := testEjector(t, ops, coordinator, expected)
	e.Mounts = func(Config, []BlockDevice) ([]Mount, error) {
		return []Mount{{MountPoint: "/mnt/disks/usb", MajorMinor: expected.MajorMinor}}, nil
	}
	resolveCalls := 0
	e.ResolveTarget = func(Config, string) (Device, error) {
		resolveCalls++
		current := expected
		if resolveCalls > 1 {
			current.DiskSeq = "999"
		}
		return current, nil
	}
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("unmount failure with changed identity should fail")
	}
	if resolveCalls < 2 || coordinator.rollback != 0 || ops.removed {
		t.Fatalf("untrusted identity reached rollback: calls=%d coordinator=%+v ops=%+v", resolveCalls, coordinator, ops)
	}
	if findReason(job.Reasons, "rollback_skipped") == nil {
		t.Fatalf("identity rollback skip was not exposed: %#v", job.Reasons)
	}
	timeline, readErr := os.ReadFile(filepath.Join(req.LogDir, "transactions", req.JobID, "timeline.jsonl"))
	if readErr != nil || !strings.Contains(string(timeline), "rollback_skipped") || strings.Contains(string(timeline), "rollback_before") {
		t.Fatalf("rollback skip journal is incorrect: err=%v timeline=%s", readErr, timeline)
	}
	if !fileExists(filepath.Join(req.LogDir, "transactions", req.JobID, "active.json")) {
		t.Fatal("identity mismatch did not preserve the transaction recovery marker")
	}
}

func TestIrreversibleAdapterPhaseNeverRollsBack(t *testing.T) {
	supported := true
	ops := &fakeOps{}
	coordinator := &fakeCoordinator{finalizeErr: &UDAdapterError{
		Action: "finalize", Supported: &supported, Version: "2025.11.18",
		Message: "mounted-state update failed", Phase: "finalizing",
	}}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	job, err := e.Run(context.Background(), req)
	if err == nil {
		t.Fatal("irreversible adapter failure should fail")
	}
	if coordinator.rollback != 0 || ops.removed || !strings.Contains(job.Message, "strictly unmounted") {
		t.Fatalf("irreversible adapter phase was mishandled: job=%+v coordinator=%+v", job, coordinator)
	}
	if reason := findReason(job.Reasons, "ud_state_unsafe"); reason == nil || !strings.Contains(reason.Advice, "normally reboot") {
		t.Fatalf("irreversible adapter advice is incomplete: %#v", job.Reasons)
	}
}

func TestInspectFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		supported  bool
	}{
		{name: "unsupported", code: "ud_capability_unavailable", supported: false},
		{name: "unsafe_state", code: "ud_state_unsafe", supported: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := &fakeOps{}
			coordinator := &fakeCoordinator{inspectErr: &UDAdapterError{Action: "inspect", Supported: &tc.supported, Version: "2025.11.18", Message: "inspection refused"}}
			e, req := testEjector(t, ops, coordinator, ejectDevice())
			job, err := e.Run(context.Background(), req)
			if err == nil || coordinator.quiesce != 0 || ops.removed {
				t.Fatalf("inspection failure crossed a side-effect boundary: job=%+v coordinator=%+v", job, coordinator)
			}
			if findReason(job.Reasons, tc.code) == nil {
				t.Fatalf("inspection failure code mismatch: want=%s reasons=%#v", tc.code, job.Reasons)
			}
		})
	}
}

func TestMultipleMountsFailBeforeUDSideEffects(t *testing.T) {
	ops, coordinator := &fakeOps{}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	e.Mounts = func(Config, []BlockDevice) ([]Mount, error) {
		return []Mount{
			{MountPoint: "/mnt/disks/usb-a", MajorMinor: "8:240"},
			{MountPoint: "/mnt/disks/usb-b", MajorMinor: "8:241"},
		}, nil
	}
	job, err := e.Run(context.Background(), req)
	if err == nil || coordinator.quiesce != 0 || coordinator.rollback != 0 || len(ops.unmounted) != 0 {
		t.Fatalf("unsupported mount layout crossed UD boundary: job=%+v coordinator=%+v ops=%+v", job, coordinator, ops)
	}
	if reason := findReason(job.Reasons, "unsupported_mount_layout"); reason == nil || !strings.Contains(reason.Advice, "ordinarily unmount") {
		t.Fatalf("mount-layout reason is incomplete: %#v", job.Reasons)
	}
}

func TestMountLayoutRaceStopsBeforeFirstUnmount(t *testing.T) {
	ops, coordinator := &fakeOps{}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	calls := 0
	e.Mounts = func(Config, []BlockDevice) ([]Mount, error) {
		calls++
		if calls == 1 {
			return []Mount{{MountPoint: "/mnt/disks/usb", MajorMinor: "8:240"}}, nil
		}
		return []Mount{
			{MountPoint: "/mnt/disks/usb", MajorMinor: "8:240"},
			{MountPoint: "/mnt/disks/usb/nested", MajorMinor: "8:240"},
		}, nil
	}
	job, err := e.Run(context.Background(), req)
	if err == nil || coordinator.quiesce != 1 || coordinator.rollback != 1 || len(ops.unmounted) != 0 {
		t.Fatalf("mount-layout race caused a partial unmount: job=%+v coordinator=%+v ops=%+v", job, coordinator, ops)
	}
	if findReason(job.Reasons, "unsupported_mount_layout") == nil {
		t.Fatalf("mount-layout race lacks a structured reason: %#v", job.Reasons)
	}
}

func TestPostUnmountUsageRegressionNeverRollsBack(t *testing.T) {
	ops, coordinator := &fakeOps{}, &fakeCoordinator{}
	e, req := testEjector(t, ops, coordinator, ejectDevice())
	e.Safety = func(_ Config, _ Device, allowSelfMounts bool) []Reason {
		if allowSelfMounts {
			return nil
		}
		return []Reason{{Code: "open_files", Message: "late reference", Advice: "close it normally"}}
	}
	job, err := e.Run(context.Background(), req)
	if err == nil || job.Stage != "verify_idle" || coordinator.finalize != 1 || coordinator.rollback != 0 || ops.removed {
		t.Fatalf("post-unmount scan failure attempted rollback: job=%+v coordinator=%+v ops=%+v", job, coordinator, ops)
	}
}
