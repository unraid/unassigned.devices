# Native UD USB safe eject

This MIT-licensed component is vendored from xO-ox-ai/unraid-usb-guardian
2026.09.18a (source commit `124bb40e2bad9180febe555fe93427d47d749987`). The matching notice is retained here and beside the web runtime.
It is built from source into the UD package by `pkg_build.sh` (Go 1.22+).
No additional plugin, daemon or network dependency is required.

The PHP and JS runtime lives in the UD source tree under `usb-guardian/`.
UD generates controls directly in its disk rows, passes the kernel identity
explicitly and calls the control refresh after replacing table content.
No Main hook, MutationObserver, HTML decorator or renderer monkey patch is used.

Release-version checks were removed for native integration. Linux/sysfs/procfs,
UD operation-barrier capabilities, transaction schema and device identity are
still verified at runtime. An installed standalone USB Guardian disables new
native operations so two independent eject coordinators cannot run together.

The core supports fully verifiable, single-disk USB mass-storage devices with at
most one active mount. It refuses boot/array/pool disks, encrypted or unsupported
storage stacks, other mount namespaces, passthrough, active references, configured
UD shares/scripts and Destructive Mode. It does not kill processes or use forced
or lazy unmounts. A completed normal unmount alone never grants unplug permission.

The sequence preserves signed device identity, normal unmount, rescanning,
exclusive access and cache synchronization, USB logical removal, node
disappearance, shfs health windows and an authoritative short-lived browser lease.
Physical unplug permission appears only after those checks pass. No software
can promise removal is safe on every hardware/firmware combination.

Native settings and forensic logs live under
`/boot/config/plugins/unassigned.devices/usb-guardian/`; runtime authority and
jobs live under `/run/ud-usb-guardian/`. Standalone plugin data is retained.
Recovery runs at array startup and package install/update. Package updates and
removal first enter maintenance under the launcher's API lock, reject queued or
active/recovery work, and block new jobs across package replacement. Failed
recovery leaves maintenance enabled. Configuration/logs survive removal.

## Checks

From this directory: `go test -count=1 ./...` and `go vet ./...`.
From the repository root, run PHP tests in `tests/usb-guardian/`,
`node tests/usb-guardian/guardian-ui-vm.test.js`, and
`node tests/usb-guardian/localization-contract.test.js`.
Run the whole source check with `bash tests/usb-guardian/check.sh`; PHP_BIN,
NODE_BIN and GO_BIN may select installed toolchains. The tests use simulated
device state and never eject a physical disk. The browser fixture is
`tests/usb-guardian/ui-fixture.html` served from the repository root; it uses
the production frontend and native PHP-rendered controls with a simulated API.
