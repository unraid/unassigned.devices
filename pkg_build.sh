#!/bin/bash
tmpdir=/tmp/tmp.$(( $RANDOM * 19318203981230 + 40 ))

version=$(date +"%Y.%m.%d")$1

mkdir -p $tmpdir

cd /tmp/GitHub/unassigned.devices/source/unassigned.devices/
chmod 0755 -R .
cp --parents -f $(find . -type f ! \( -iname "pkg_build.sh" -o -iname "sftp-config.json"  \) ) $tmpdir/
cd $tmpdir
makepkg -l y -c y /tmp/GitHub/unassigned.devices/archive/unassigned.devices-${version}-x86_64-1.txz
rm -rf $tmpdir
echo "MD5 Unassigned Devices::"
md5sum /tmp/GitHub/unassigned.devices/archive/unassigned.devices-${version}-x86_64-1.txz


mkdir -p $tmpdir

cd /tmp/GitHub/unassigned.devices/source/unassigned.devices.preclear/
chmod 0755 -R .
cp --parents -f $(find . -type f ! \( -iname "pkg_build.sh" -o -iname "sftp-config.json"  \) ) $tmpdir/
cd $tmpdir
makepkg -l y -c y /tmp/GitHub/unassigned.devices/archive/unassigned.devices.preclear-${version}-x86_64-1.txz
rm -rf $tmpdir
echo "MD5 Preclear::"
md5sum /tmp/GitHub/unassigned.devices/archive/unassigned.devices.preclear-${version}-x86_64-1.txz
