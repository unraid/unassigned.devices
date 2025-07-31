#!/bin/bash

rm -rf "/tmp/GitHub/unassigned.devices/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/"
mkdir -p "/tmp/GitHub/unassigned.devices/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/"

rm -rf "/tmp/GitHub/unassigned.devices/source/unassigned.devices.preclear/usr/local/emhttp/plugins/unassigned.devices.preclear/"
mkdir -p "/tmp/GitHub/unassigned.devices/source/unassigned.devices.preclear/usr/local/emhttp/plugins/unassigned.devices.preclear/"

cp /usr/local/emhttp/plugins/unassigned.devices/* /tmp/GitHub/unassigned.devices/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices -R -v -p
cp /usr/local/emhttp/plugins/unassigned.devices.preclear/* /tmp/GitHub/unassigned.devices/source/unassigned.devices.preclear/usr/local/emhttp/plugins/unassigned.devices.preclear/ -R -v -p

cd /tmp/GitHub/unassigned.devices/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices

# Delete symlinks made into the code by the plugin installer
find . -type l -exec rm -fv "{}" \;

# Delete Apple Metadata files
find . -maxdepth 9999 -noleaf -type f -name "._*" -exec rm -v "{}" \;
rm -f  ud.md5
find . -type f -exec md5sum {} + > /tmp/ud.md5
mv /tmp/ud.md5 ud.md5

cd /tmp/GitHub/unassigned.devices/source/unassigned.devices.preclear/usr/local/emhttp/plugins/unassigned.devices.preclear/

# Delete symlinks made into the code by the plugin installer
find . -type l -exec rm -fv "{}" \;

# Delete Apple Metadata files
find . -maxdepth 9999 -noleaf -type f -name "._*" -exec rm -v "{}" \;
rm -f  ud.md5
find . -type f -exec md5sum {} + > /tmp/ud.md5
mv /tmp/ud.md5 ud.md5