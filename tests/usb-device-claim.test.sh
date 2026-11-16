#!/bin/sh
# Linux: sh tests/usb-device-claim.test.sh
# Optional isolated loop-device checks: UD_TEST_LOOP=1 sh tests/usb-device-claim.test.sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d /tmp/ud-claim-test.XXXXXX)
loop=
claim=
cleanup() {
  exec 3>&-
  if [ -n "$claim" ]; then wait "$claim" || true; fi
  if [ -n "$loop" ] && [ "$(losetup -n -O BACK-FILE "$loop")" = "$tmp/image" ]; then
    mountpoint -q "$tmp/mnt" && umount "$tmp/mnt"
    losetup -d "$loop"
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror "$repo/tools/usb-device-claim.c" -o "$tmp/claim"
refuse() {
  expected=$1; shift
  if "$tmp/claim" "$@" > "$tmp/result"; then echo 'Unexpected acceptance' >&2; exit 1; fi
  [ "$(cat "$tmp/result")" = "$expected" ]
}
refuse changed
refuse changed /dev/none 0
refuse changed /dev/none -1
refuse changed /dev/none 18446744073709551616
refuse inspection "$tmp/missing" 1
printf 'sentinel data\n' > "$tmp/regular"
refuse changed "$tmp/regular" 1
ln -s "$tmp/regular" "$tmp/link"
refuse inspection "$tmp/link" 1
[ "$(cat "$tmp/regular")" = 'sentinel data' ]
[ ! -e "$tmp/missing" ]
echo '9 real helper compilation/input/non-writing checks passed'

if [ "${UD_TEST_LOOP:-0}" = 1 ]; then
  # Format a new file, never an existing block device.
  truncate -s 16M "$tmp/image"
  mkfs.ext4 -q -F "$tmp/image"
  loop=$(losetup --find --show "$tmp/image")
  [ "$(losetup -n -O BACK-FILE "$loop")" = "$tmp/image" ]
  sequence=$(cat "/sys/class/block/$(basename "$loop")/diskseq")
  refuse changed "$loop" 18446744073709551615
  mkdir "$tmp/mnt"
  mkfifo "$tmp/input"
  exec 3<> "$tmp/input"
  "$tmp/claim" "$loop" "$sequence" < "$tmp/input" > "$tmp/ready" 3>&- &
  claim=$!
  tries=0
  until [ "$(cat "$tmp/ready")" = ready ]; do
    tries=$((tries + 1)); [ "$tries" -lt 200 ]
    kill -0 "$claim"
    sleep 0.01
  done
  refuse busy "$loop" "$sequence"
  if mount "$loop" "$tmp/mnt" 2> "$tmp/mount-error"; then
    echo 'Exclusive claim failed to block mount' >&2; exit 1
  fi
  exec 3>&-
  wait "$claim"
  claim=
  mount "$loop" "$tmp/mnt"
  refuse busy "$loop" "$sequence"
  umount "$tmp/mnt"
  echo '6 isolated loop-device identity/exclusion/flush/release checks passed'
fi
