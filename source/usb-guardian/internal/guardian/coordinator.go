package guardian

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

type Coordinator interface {
	Inspect(context.Context, Device, string) error
	Quiesce(context.Context, Device, string) error
	Finalize(context.Context, Device, string) error
	Rollback(context.Context, Device, string) error
}

type UDCoordinator struct{ Config Config }

type UDAdapterError struct {
	Action    string
	Supported *bool
	Version   string
	Message   string
	Phase     string
	Details   map[string]any
}

func (e *UDAdapterError) Error() string {
	message := e.Message
	if message == "" {
		message = "Unassigned Devices adapter refused the operation"
	}
	if e.Supported != nil && !*e.Supported {
		if e.Version != "" {
			return fmt.Sprintf("unsupported UD version %s: %s", e.Version, message)
		}
		return "unsupported Unassigned Devices integration: " + message
	}
	if e.Action == "" {
		return message
	}
	if e.Phase != "" {
		return fmt.Sprintf("UD adapter %s failed in phase %s: %s", e.Action, e.Phase, message)
	}
	return fmt.Sprintf("UD adapter %s failed: %s", e.Action, message)
}

func (e *UDAdapterError) IsUnsupported() bool {
	return e != nil && e.Supported != nil && !*e.Supported
}

func (e *UDAdapterError) IsIrreversible() bool {
	if e == nil {
		return false
	}
	switch e.Phase {
	case "finalizing", "finalized", "releasing_ud_markers", "marker_release_failed":
		return true
	default:
		return false
	}
}

type adapterResponse struct {
	OK        bool           `json:"ok"`
	Supported *bool          `json:"supported,omitempty"`
	Error     string         `json:"error,omitempty"`
	Message   string         `json:"message,omitempty"`
	Version   string         `json:"version,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

func adapterResponseError(action string, response adapterResponse) error {
	if response.OK && (response.Supported == nil || *response.Supported) {
		return nil
	}
	message := response.Error
	if message == "" {
		message = response.Message
	}
	phase, _ := response.Details["phase"].(string)
	return &UDAdapterError{
		Action:    action,
		Supported: response.Supported,
		Version:   response.Version,
		Message:   message,
		Phase:     phase,
		Details:   response.Details,
	}
}

func udInspectionReason(err error) Reason {
	var adapterErr *UDAdapterError
	if errors.As(err, &adapterErr) {
		if adapterErr.IsUnsupported() {
			return Reason{
				Code:    "ud_capability_unavailable",
				Message: "the installed Unassigned Devices integration is not compatible",
				Detail:  adapterErr.Error(),
				Advice:  "Required Unassigned Devices runtime interfaces are unavailable. Refresh the page or restart Unraid.",
			}
		}
		if adapterErr.Supported != nil && *adapterErr.Supported {
			return Reason{
				Code:    "ud_state_unsafe",
				Message: "Unassigned Devices reported unsafe or inconsistent device state",
				Detail:  adapterErr.Error(),
				Advice:  "Keep the device connected. Resolve the reported Unassigned Devices state or topology problem, then check again.",
			}
		}
	}
	return Reason{
		Code:    "inspection_failed",
		Message: "Unassigned Devices integration could not be verified",
		Detail:  err.Error(),
		Advice:  "Keep the device connected. Restore the USB Guardian adapter and Unassigned Devices runtime, then check again.",
	}
}

func (u UDCoordinator) Inspect(ctx context.Context, d Device, jobID string) error {
	return u.run(ctx, "inspect", d, jobID)
}
func (u UDCoordinator) Quiesce(ctx context.Context, d Device, jobID string) error {
	return u.run(ctx, "quiesce", d, jobID)
}
func (u UDCoordinator) Finalize(ctx context.Context, d Device, jobID string) error {
	return u.run(ctx, "finalize", d, jobID)
}
func (u UDCoordinator) Rollback(ctx context.Context, d Device, jobID string) error {
	return u.run(ctx, "rollback", d, jobID)
}

func (u UDCoordinator) run(parent context.Context, action string, d Device, jobID string) error {
	if u.Config.UDAdapter == "-" {
		return nil
	}
	if u.Config.UDAdapter == "" {
		return errors.New("UD adapter path is not configured")
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, u.Config.UDAdapter, action, d.KernelName, jobID)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("UD adapter %s timed out: %w", action, ctx.Err())
		}
		return fmt.Errorf("UD adapter %s failed: %w: %s", action, err, stderr.String())
	}
	var response adapterResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return fmt.Errorf("UD adapter %s returned invalid JSON: %w", action, err)
	}
	return adapterResponseError(action, response)
}

func runCommand(parent context.Context, command []string, extra ...string) error {
	if len(command) == 0 || command[0] == "" {
		return errors.New("empty hook command")
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	args := append(append([]string{}, command[1:]...), extra...)
	cmd := exec.CommandContext(ctx, command[0], args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s: %w: %s", command[0], err, stderr.String())
	}
	return nil
}

type NoopCoordinator struct{}

func (NoopCoordinator) Inspect(context.Context, Device, string) error  { return nil }
func (NoopCoordinator) Quiesce(context.Context, Device, string) error  { return nil }
func (NoopCoordinator) Finalize(context.Context, Device, string) error { return nil }
func (NoopCoordinator) Rollback(context.Context, Device, string) error { return nil }
