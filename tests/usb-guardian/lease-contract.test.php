<?php
declare(strict_types=1);

require_once __DIR__.'/../../source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/include/api_helpers.php';

function lease_expect_failure(callable $callback, string $message, string $contains = ''): GuardianApiException
{
    try {
        $callback();
    } catch (GuardianApiException $exception) {
        if ($contains !== '' && !str_contains($exception->getMessage(), $contains)) {
            throw new RuntimeException($message.' Unexpected error: '.$exception->getMessage());
        }
        return $exception;
    }
    throw new RuntimeException($message);
}

function lease_remove_tree(string $path): void
{
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) {
        return;
    }
    foreach (scandir($path) ?: [] as $entry) {
        if ($entry !== '.' && $entry !== '..') {
            lease_remove_tree($path.DIRECTORY_SEPARATOR.$entry);
        }
    }
    @rmdir($path);
}

function lease_write_usb_entry(string $sysRoot, string $name, string $vid, string $pid, ?string $serial): string
{
    $path = $sysRoot.DIRECTORY_SEPARATOR.'bus'.DIRECTORY_SEPARATOR.'usb'.DIRECTORY_SEPARATOR.'devices'.DIRECTORY_SEPARATOR.$name;
    if (!is_dir($path) && !mkdir($path, 0777, true) && !is_dir($path)) {
        throw new RuntimeException('Unable to create USB fixture entry.');
    }
    file_put_contents($path.DIRECTORY_SEPARATOR.'idVendor', $vid."\n");
    file_put_contents($path.DIRECTORY_SEPARATOR.'idProduct', $pid."\n");
    if ($serial !== null) {
        file_put_contents($path.DIRECTORY_SEPARATOR.'serial', $serial."\n");
    }
    return $path;
}

$root = sys_get_temp_dir().DIRECTORY_SEPARATOR.'usb-guardian-lease-'.bin2hex(random_bytes(8));
$jobDir = $root.DIRECTORY_SEPARATOR.'jobs';
$sysRoot = $root.DIRECTORY_SEPARATOR.'sys';
mkdir($jobDir, 0777, true);
mkdir($sysRoot.DIRECTORY_SEPARATOR.'bus'.DIRECTORY_SEPARATOR.'usb'.DIRECTORY_SEPARATOR.'devices', 0777, true);
mkdir($sysRoot.DIRECTORY_SEPARATOR.'kernel', 0777, true);
file_put_contents($sysRoot.DIRECTORY_SEPARATOR.'kernel'.DIRECTORY_SEPARATOR.'uevent_seqnum', "100\n");
register_shutdown_function(static fn() => lease_remove_tree($root));
$rootHub = lease_write_usb_entry($sysRoot, 'usb1', '1d6b', '0002', 'ROOT-HUB');

$boot = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
$jobId = '11111111-1111-4111-8111-111111111111';
$identity = [
    'usb_path' => 'devices/platform/xhci-hcd.0/usb1/1-2',
    'usb_vid' => '0781',
    'usb_pid' => '5581',
    'usb_serial' => 'USB-SERIAL-1',
];
$job = [
    'schema_version' => 1,
    'job_id' => $jobId,
    'state' => 'completed',
    'terminal' => true,
    'safe_to_unplug' => true,
    'device' => $identity,
];
$authority = [
    'schema_version' => 1,
    'boot_id' => $boot,
    'job_id' => $jobId,
    'generation' => 7,
];
$jobPath = $jobDir.DIRECTORY_SEPARATOR.$jobId.'.json';
file_put_contents($jobPath, json_encode($job, JSON_THROW_ON_ERROR)."\n");
$readJob = guardian_read_lease_job_file($jobId, $jobDir);
if (($readJob['job_id'] ?? '') !== $jobId) {
    throw new RuntimeException('Bounded regular job reader did not return the authoritative job.');
}
$lease = guardian_validate_lease_state($jobId, 7, $authority, $readJob, $sysRoot, $boot);
if (($lease['device_absent'] ?? false) !== true
    || ($lease['identity']['usb_serial'] ?? '') !== $identity['usb_serial']
    || ($lease['job']['safe_to_unplug'] ?? false) !== true) {
    throw new RuntimeException('Valid absent-device lease was not accepted.');
}

lease_expect_failure(
    static fn() => guardian_validate_lease_state($jobId, 8, $authority, $job, $sysRoot, $boot),
    'Mismatched authority generation must fail.',
    'no longer the current authority',
);
$unsafe = $job;
$unsafe['terminal'] = false;
lease_expect_failure(
    static fn() => guardian_validate_lease_state($jobId, 7, $authority, $unsafe, $sysRoot, $boot),
    'A non-terminal job must not issue a lease.',
    'not a completed safe-eject result',
);
$invalidIdentity = $job;
$invalidIdentity['device']['usb_path'] = '../../sys/bus/usb/devices/1-2';
lease_expect_failure(
    static fn() => guardian_lease_identity_from_job($jobId, $invalidIdentity),
    'A non-canonical USB path must fail.',
    'invalid USB sysfs path',
);
$invalidIdentity = $job;
$invalidIdentity['device']['usb_vid'] = '781';
lease_expect_failure(
    static fn() => guardian_lease_identity_from_job($jobId, $invalidIdentity),
    'A malformed VID must fail.',
    'VID/PID',
);

$original = $sysRoot.DIRECTORY_SEPARATOR.str_replace('/', DIRECTORY_SEPARATOR, $identity['usb_path']);
mkdir($original, 0777, true);
lease_expect_failure(
    static fn() => guardian_assert_lease_usb_absent($identity, $sysRoot),
    'The original raw sysfs path must fail.',
    'original USB sysfs path',
);
lease_remove_tree($original);

$samePort = lease_write_usb_entry($sysRoot, '1-2', '9999', '0001', 'OTHER');
lease_expect_failure(
    static fn() => guardian_assert_lease_usb_absent($identity, $sysRoot),
    'A device on the original port must fail regardless of identity.',
    'original physical port',
);
lease_remove_tree($samePort);

$sameIdentity = lease_write_usb_entry($sysRoot, '1-3', '0781', '5581', 'USB-SERIAL-1');
lease_expect_failure(
    static fn() => guardian_assert_lease_usb_absent($identity, $sysRoot),
    'The same VID/PID/serial on another port must fail.',
    'same USB VID/PID/serial',
);
file_put_contents($sameIdentity.DIRECTORY_SEPARATOR.'serial', "DIFFERENT\n");
guardian_assert_lease_usb_absent($identity, $sysRoot);
@unlink($sameIdentity.DIRECTORY_SEPARATOR.'serial');
$exception = lease_expect_failure(
    static fn() => guardian_assert_lease_usb_absent($identity, $sysRoot),
    'A matching live VID/PID with no readable serial must fail closed.',
    'has no readable serial number',
);
if (($exception->details['reason']['code'] ?? '') !== 'usb_identity_ambiguous_live_serial_missing') {
    throw new RuntimeException('Missing live serial ambiguity did not return a clear reason code.');
}
file_put_contents($sameIdentity.DIRECTORY_SEPARATOR.'serial', "DIFFERENT\n");

$noSerial = $identity;
$noSerial['usb_serial'] = '';
$exception = lease_expect_failure(
    static fn() => guardian_assert_lease_usb_absent($noSerial, $sysRoot),
    'A serial-less identity must fail when any same VID/PID device is present.',
    'has no serial number',
);
if (($exception->details['reason']['code'] ?? '') !== 'usb_identity_ambiguous_no_serial') {
    throw new RuntimeException('Serial-less ambiguity did not return a clear reason code.');
}
file_put_contents($sameIdentity.DIRECTORY_SEPARATOR.'idVendor', "not-hex\n");
lease_expect_failure(
    static fn() => guardian_assert_lease_usb_absent($identity, $sysRoot),
    'Malformed live sysfs identity must fail closed.',
    'invalid VID/PID',
);
lease_remove_tree($sameIdentity);

$unreadableIdentity = $sysRoot.DIRECTORY_SEPARATOR.'bus'.DIRECTORY_SEPARATOR.'usb'.DIRECTORY_SEPARATOR.'devices'.DIRECTORY_SEPARATOR.'1-4';
mkdir($unreadableIdentity);
lease_expect_failure(
    static fn() => guardian_assert_lease_usb_absent($identity, $sysRoot),
    'A physical USB inventory entry without identity attributes must fail closed.',
    'idVendor is unavailable',
);
lease_remove_tree($unreadableIdentity);

lease_remove_tree($rootHub);
lease_expect_failure(
    static fn() => guardian_assert_lease_usb_absent($identity, $sysRoot),
    'An empty USB inventory must fail closed.',
    'inventory is empty',
);
$rootHub = lease_write_usb_entry($sysRoot, 'usb1', '1d6b', '0002', 'ROOT-HUB');
file_put_contents($sysRoot.DIRECTORY_SEPARATOR.'kernel'.DIRECTORY_SEPARATOR.'uevent_seqnum', "invalid\n");
lease_expect_failure(
    static fn() => guardian_assert_lease_usb_absent($identity, $sysRoot),
    'A malformed kernel uevent sequence must fail closed.',
    'uevent sequence is invalid',
);
file_put_contents($sysRoot.DIRECTORY_SEPARATOR.'kernel'.DIRECTORY_SEPARATOR.'uevent_seqnum', "101\n");
guardian_assert_lease_usb_absent($identity, $sysRoot);

file_put_contents($jobPath, '{broken');
lease_expect_failure(
    static fn() => guardian_read_lease_job_file($jobId, $jobDir),
    'Malformed job JSON must fail.',
    'invalid JSON',
);
file_put_contents($jobPath, str_repeat('x', GUARDIAN_LEASE_JOB_MAX_BYTES + 1));
lease_expect_failure(
    static fn() => guardian_read_lease_job_file($jobId, $jobDir),
    'Oversized job JSON must fail.',
    'invalid size',
);
@unlink($jobPath);
$target = $jobDir.DIRECTORY_SEPARATOR.'target.json';
file_put_contents($target, json_encode($job, JSON_THROW_ON_ERROR)."\n");
if (@symlink($target, $jobPath)) {
    lease_expect_failure(
        static fn() => guardian_read_lease_job_file($jobId, $jobDir),
        'A symlink job file must fail.',
        'not a regular file',
    );
    @unlink($jobPath);
}

$helpersSource = (string)file_get_contents(__DIR__.'/../../source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/include/api_helpers.php');
if (substr_count($helpersSource, "guardian_read_lease_sysfs_attribute(\$ueventPath, 'uevent_seqnum', true)") !== 2) {
    throw new RuntimeException('Lease USB absence verification must bracket its sysfs scan with two uevent sequence reads.');
}
$leaseStart = strpos($helpersSource, 'function guardian_lease(');
$leaseEnd = $leaseStart === false ? false : strpos($helpersSource, "\nfunction ", $leaseStart + 20);
$leaseSource = ($leaseStart !== false && $leaseEnd !== false) ? substr($helpersSource, $leaseStart, $leaseEnd - $leaseStart) : '';
foreach (["api.lock", 'LOCK_SH', 'guardian_read_authority()', 'guardian_read_lease_job_file', 'guardian_validate_lease_state'] as $needle) {
    if (!str_contains($leaseSource, $needle)) {
        throw new RuntimeException("Lease endpoint is missing shared-lock contract: {$needle}");
    }
}
$apiSource = (string)file_get_contents(__DIR__.'/../../source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/api.php');
foreach (["case 'lease':", "guardian_request_string('job_id', 36, 36", "guardian_request_string('generation', 1, 19"] as $needle) {
    if (!str_contains($apiSource, $needle)) {
        throw new RuntimeException("Lease API request validation is missing: {$needle}");
    }
}

echo "USB Guardian lease contract tests passed.\n";
