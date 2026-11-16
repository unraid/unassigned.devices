package guardian

import (
	"errors"
	"strings"
	"testing"
)

func boolPointer(value bool) *bool { return &value }

func TestAdapterResponseErrorPreservesStructuredState(t *testing.T) {
	err := adapterResponseError("finalize", adapterResponse{
		OK:        false,
		Supported: boolPointer(true),
		Version:   "2025.11.18",
		Error:     "mounted state update failed",
		Details:   map[string]any{"phase": "finalizing", "edition": "official"},
	})
	var adapterErr *UDAdapterError
	if !errors.As(err, &adapterErr) {
		t.Fatalf("adapter failure is not structured: %T %v", err, err)
	}
	if adapterErr.Action != "finalize" || adapterErr.Phase != "finalizing" || adapterErr.IsUnsupported() || !adapterErr.IsIrreversible() {
		t.Fatalf("structured adapter state was lost: %+v", adapterErr)
	}
	if adapterErr.Details["edition"] != "official" {
		t.Fatalf("adapter details were lost: %+v", adapterErr.Details)
	}
}

func TestUDInspectionReasonSeparatesCompatibilityAndState(t *testing.T) {
	unsupported := &UDAdapterError{Action: "inspect", Supported: boolPointer(false), Version: "2099.01.01", Message: "required capability missing"}
	if reason := udInspectionReason(unsupported); reason.Code != "ud_capability_unavailable" || !strings.Contains(reason.Advice, "runtime interfaces") {
		t.Fatalf("unsupported version was misclassified: %+v", reason)
	}

	unsafeState := &UDAdapterError{Action: "inspect", Supported: boolPointer(true), Version: "2025.11.18", Message: "mountpoint belongs to another device"}
	if reason := udInspectionReason(unsafeState); reason.Code != "ud_state_unsafe" || strings.Contains(strings.ToLower(reason.Advice), "update") {
		t.Fatalf("supported UD state error was misclassified: %+v", reason)
	}

	if reason := udInspectionReason(errors.New("adapter executable unavailable")); reason.Code != "inspection_failed" {
		t.Fatalf("transport failure was misclassified: %+v", reason)
	}
}
