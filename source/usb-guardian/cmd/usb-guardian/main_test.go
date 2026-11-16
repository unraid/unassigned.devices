package main

import (
	"fmt"
	"testing"

	"github.com/xO-ox-ai/unraid-usb-guardian/internal/guardian"
)

func TestErrorResponseIncludesPersistentLogMountDiagnosis(t *testing.T) {
	cause := &guardian.PersistentLogMountError{
		Code:    "persistent_log_mount_missing",
		Message: "boot mount is missing",
		Detail:  "found 0 /boot mountinfo entries",
		Advice:  "restore /boot and retry",
	}
	response := errorResponse(fmt.Errorf("maintenance failed: %w", cause))
	for key, expected := range map[string]string{
		"code":    cause.Code,
		"message": cause.Message,
		"detail":  cause.Detail,
		"advice":  cause.Advice,
	} {
		if got, ok := response[key].(string); !ok || got != expected {
			t.Fatalf("%s diagnosis = %#v, want %q", key, response[key], expected)
		}
	}
}
