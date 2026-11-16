package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xO-ox-ai/unraid-usb-guardian/internal/guardian"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	ctx := context.Background()
	switch args[0] {
	case "list", "discover":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := fs.String("config", "/boot/config/plugins/unassigned.devices/usb-guardian/usb.guardian.cfg", "configuration path")
		asJSON := fs.Bool("json", false, "emit JSON")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		cfg, err := guardian.LoadConfig(*configPath)
		if err != nil {
			return printError(err)
		}
		if err := guardian.MaintainLogs(filepath.Join(filepath.Dir(*configPath), "logs"), cfg); err != nil {
			return printError(err)
		}
		devices, err := guardian.Discover(cfg)
		if err != nil {
			return printError(err)
		}
		if *asJSON {
			return printJSON(map[string]any{"schema_version": guardian.SchemaVersion, "devices": devices})
		}
		for _, d := range devices {
			state := "eligible"
			if !d.Eligible {
				state = "blocked"
			}
			fmt.Printf("%s\t%s\t%s\n", d.DevX, state, d.Model)
		}
		return 0
	case "inspect":
		fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := fs.String("config", "/boot/config/plugins/unassigned.devices/usb-guardian/usb.guardian.cfg", "configuration path")
		target := fs.String("target", "", "opaque target token")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		cfg, err := guardian.LoadConfig(*configPath)
		if err != nil {
			return printError(err)
		}
		d, err := guardian.InspectToken(cfg, *target)
		if err != nil {
			return printError(err)
		}
		return printJSON(d)
	case "eject":
		fs := flag.NewFlagSet("eject", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := fs.String("config", "/boot/config/plugins/unassigned.devices/usb-guardian/usb.guardian.cfg", "configuration path")
		target := fs.String("target", "", "opaque target token")
		jobID := fs.String("job-id", "", "job identifier")
		jobDir := fs.String("job-dir", "", "runtime job directory")
		logDir := fs.String("log-dir", "", "persistent transaction log directory")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		cfg, err := guardian.LoadConfig(*configPath)
		if err != nil {
			return printError(err)
		}
		job, err := (guardian.Ejector{Config: cfg}).Run(ctx, guardian.EjectRequest{Target: *target, JobID: *jobID, JobDir: *jobDir, LogDir: *logDir})
		_ = json.NewEncoder(os.Stdout).Encode(job)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "status":
		fs := flag.NewFlagSet("status", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		jobID := fs.String("job-id", "", "job identifier")
		jobDir := fs.String("job-dir", "", "runtime job directory")
		asJSON := fs.Bool("json", false, "emit JSON")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		job, err := (guardian.JobStore{Dir: *jobDir}).Read(*jobID)
		if err != nil {
			return printError(err)
		}
		if *asJSON {
			return printJSON(job)
		}
		fmt.Printf("%s\t%s\t%d%%\t%s\n", job.ID, job.Status, job.Progress, job.Message)
		return 0
	case "recover":
		fs := flag.NewFlagSet("recover", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := fs.String("config", "/boot/config/plugins/unassigned.devices/usb-guardian/usb.guardian.cfg", "configuration path")
		jobDir := fs.String("job-dir", "", "runtime job directory")
		logDir := fs.String("log-dir", "", "persistent transaction log directory")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		cfg, err := guardian.LoadConfig(*configPath)
		if err != nil {
			return printError(err)
		}
		result, err := guardian.RecoverInterrupted(cfg, *jobDir, *logDir)
		_ = json.NewEncoder(os.Stdout).Encode(result)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "diagnostics":
		fs := flag.NewFlagSet("diagnostics", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := fs.String("config", "/boot/config/plugins/unassigned.devices/usb-guardian/usb.guardian.cfg", "configuration path")
		logDir := fs.String("log-dir", "", "persistent transaction log directory")
		output := fs.String("output", "", "output ZIP path")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		cfg, err := guardian.LoadConfig(*configPath)
		if err != nil {
			return printError(err)
		}
		if err := guardian.CreateDiagnosticsArchive(cfg, *logDir, *output); err != nil {
			return printError(err)
		}
		return printJSON(map[string]any{"ok": true, "output": *output})
	case "version", "--version", "-version":
		fmt.Println(version)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "unknown command: "+args[0])
		usage()
		return 2
	}
}

func printJSON(value any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return printError(err)
	}
	return 0
}

func printError(err error) int {
	_ = json.NewEncoder(os.Stderr).Encode(errorResponse(err))
	return 1
}

func errorResponse(err error) map[string]any {
	response := map[string]any{"error": err.Error()}
	var mountErr *guardian.PersistentLogMountError
	if errors.As(err, &mountErr) {
		response["code"] = mountErr.Code
		response["message"] = mountErr.Message
		response["detail"] = mountErr.Detail
		response["advice"] = mountErr.Advice
	}
	return response
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: usb-guardian <list|inspect|eject|status|recover|diagnostics|version> [options]")
}
