<?php
declare(strict_types=1);

$root = dirname(__DIR__, 2);
$api = (string)file_get_contents($root.'/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/api.php');
$settings = (string)file_get_contents($root.'/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/assets/settings.js');
$guardian = (string)file_get_contents($root.'/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/assets/guardian.js');
$settingsPage = (string)file_get_contents($root.'/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/UnassignedDevicesSafeEject.page');
$mainHook = (string)file_get_contents($root.'/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/UnassignedDevices.page');

$assert = static function (bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, $message."\n");
        exit(1);
    }
};

$assert(str_contains($api, "Unraid's PHP auto_prepend validates every POST"), 'API must document the upstream Unraid CSRF authority.');
$assert(!str_contains($api, "\$_POST['csrf_token']"), 'API must not revalidate a token consumed by Unraid auto_prepend.');
$assert(!str_contains($api, "HTTP_X_CSRF_TOKEN"), 'API must not revalidate a header consumed by Unraid auto_prepend.');
$assert(!str_contains($api, 'CSRF validation failed.'), 'Legacy duplicate CSRF rejection is still present.');

foreach ([$settings, $guardian] as $client) {
    $assert(str_contains($client, 'csrf_token: runtime.csrfToken'), 'Every fetch client must submit the Unraid CSRF token.');
    $assert(str_contains($client, 'Unraid rejected the request. Refresh this page and try again.'), 'Every fetch client must explain an upstream empty rejection.');
}
foreach ([$settingsPage, $mainHook] as $page) {
    $assert(str_contains($page, "['csrf_token']"), 'Each rendered page must inject Unraid\'s current CSRF token.');
}

fwrite(STDOUT, "Unraid CSRF integration contract tests passed.\n");
