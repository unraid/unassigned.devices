#!/bin/bash
set -e
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
tmpdir=/tmp/tmp.$(( $RANDOM * 19318203981230 + 40 ))

version=$(date +"%Y.%m.%d")$1

mkdir -p $tmpdir

cd "$repo_root/source/unassigned.devices/"
chmod 0755 -R .
cp --parents -f $(find . -type f ! \( -iname "pkg_build.sh" -o -iname "sftp-config.json"  \) ) $tmpdir/
# Compile from the vendored MIT source; the release has no external plugin dependency.
mkdir -p "$tmpdir/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/bin"
(
  cd "$repo_root/source/usb-guardian"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath \
    -ldflags "-s -w -X main.version=$version" \
    -o "$tmpdir/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/bin/usb-guardian" ./cmd/usb-guardian
)
cd $tmpdir
makepkg -l y -c y "${repo_root}/archive/unassigned.devices-${version}-x86_64-1.txz"
rm -rf $tmpdir
echo "MD5 Unassigned Devices::"
md5sum "${repo_root}/archive/unassigned.devices-${version}-x86_64-1.txz"


mkdir -p $tmpdir

cd "$repo_root/source/unassigned.devices.preclear/"
chmod 0755 -R .
cp --parents -f $(find . -type f ! \( -iname "pkg_build.sh" -o -iname "sftp-config.json"  \) ) $tmpdir/
cd $tmpdir
makepkg -l y -c y "${repo_root}/archive/unassigned.devices.preclear-${version}-x86_64-1.txz"
rm -rf $tmpdir
echo "MD5 Preclear::"
md5sum "${repo_root}/archive/unassigned.devices.preclear-${version}-x86_64-1.txz"
