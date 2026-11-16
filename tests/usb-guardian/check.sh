#!/bin/bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
php_bin="${PHP_BIN:-php}"
node_bin="${NODE_BIN:-node}"
go_bin="${GO_BIN:-go}"
(
  cd source/usb-guardian
  "$go_bin" test -count=1 ./...
  "$go_bin" vet ./...
)
for test in tests/usb-guardian/*.test.php; do "$php_bin" -n "$test"; done
"$node_bin" tests/usb-guardian/guardian-ui-vm.test.js
"$node_bin" tests/usb-guardian/localization-contract.test.js
runtime=source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices
for file in "$runtime"/usb-guardian/include/*.php "$runtime"/usb-guardian/scripts/*.php "$runtime"/usb-guardian/api.php "$runtime"/include/SafeEject.php "$runtime"/include/UnassignedDevices.php "$runtime"/UnassignedDevices.page "$runtime"/UnassignedDevicesSafeEject.page; do
  "$php_bin" -d short_open_tag=1 -l "$file"
done
for file in "$runtime"/usb-guardian/assets/*.js; do "$node_bin" --check "$file"; done
bash -n pkg_build.sh
bash -n "$runtime"/usb-guardian/scripts/start
git diff --check
