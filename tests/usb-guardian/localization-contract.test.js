'use strict';
const fs = require('fs');
const root = 'source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices';
const en = JSON.parse(fs.readFileSync(`${root}/usb-guardian/language/en_US.json`, 'utf8'));
const zh = JSON.parse(fs.readFileSync(`${root}/usb-guardian/language/zh_CN.json`, 'utf8'));
for (const key of Object.keys(en)) {
  if (typeof zh[key] !== 'string' || !zh[key]) throw new Error(`Missing Chinese translation: ${key}`);
}
const js = fs.readFileSync(`${root}/usb-guardian/assets/guardian.js`, 'utf8');
if (/MutationObserver|updatePageContent\s*=|decorateDiskRows|rowDeviceDescriptor/.test(js)) throw new Error('Native UI must not discover or inject table controls.');
const settings = fs.readFileSync(`${root}/UnassignedDevicesSafeEject.page`, 'utf8');
if (!settings.includes('Menu="UnassignedDevicesSettings"') || !settings.includes("'i18n' => usb_guardian_catalog()")) throw new Error('Settings must use the UD menu and selected catalog.');
console.log(`Native localization: ${Object.keys(en).length} catalog entries checked.`);
