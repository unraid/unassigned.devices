<?php
declare(strict_types=1);

$path = __DIR__.'/../../source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/scripts/ud_adapter.php';
$source = (string)file_get_contents($path);
$start = strpos($source, "<?php\n");
$end = strrpos($source, "\nob_start();\ntry {");
if ($start === false || $end === false || $end <= $start) {
    throw new RuntimeException('Unable to isolate UD adapter definitions.');
}
eval(substr($source, $start + 6, $end - ($start + 6)));
ini_set('display_errors', '1');
error_reporting(E_ALL);

$loaderStart = strpos($source, 'function adapter_require_supported_ud(): array');
$loaderEnd = strpos($source, "\nfunction adapter_find_disk", $loaderStart ?: 0);
$entrypoint = strrpos($source, "\nob_start();\ntry {");
if ($loaderStart === false || $loaderEnd === false || $entrypoint === false
    || str_contains(substr($source, $loaderStart, $loaderEnd - $loaderStart), 'require_once ADAPTER_UD_LIB')
    || !str_contains(substr($source, $entrypoint), 'require_once ADAPTER_UD_LIB')) {
    throw new RuntimeException('The UD library must be loaded only from the adapter global scope.');
}

function expect_failure(callable $callback, string $message): void
{
    try {
        $callback();
    } catch (RuntimeException) {
        return;
    }
    throw new RuntimeException($message);
}

function assert_same(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($message.' expected='.var_export($expected, true).' actual='.var_export($actual, true));
    }
}

if (str_contains($source, 'version_compare(') || str_contains($source, 'ADAPTER_MIN_UD_VERSION')) {
    throw new RuntimeException('Native safe eject must not gate device operations on a plugin release date.');
}

function get_all_disks_info(): array
{
    return [];
}

function get_config(string $section, string $key): string
{
    return '';
}

define('UD_CONFIG_FILE', __FILE__);
$cfg = ['Config' => []];
$paths = ['unmounting' => '/var/state/unassigned.devices/unmounting_%s.state'];
assert_same('', adapter_ud_runtime_capability_error(), 'The current UD runtime contract was rejected.');
$paths['unmounting'] = '/changed/unmounting_%s.state';
if (!str_contains(adapter_ud_runtime_capability_error(), 'operation-barrier')) {
    throw new RuntimeException('A changed UD operation-barrier contract was not rejected.');
}
$paths['unmounting'] = '/var/state/unassigned.devices/unmounting_%s.state';

$bootMountinfo = implode("\n", [
    '1 0 0:1 / / rw - rootfs rootfs rw',
    '36 1 8:1 / /boot rw - vfat /dev/sda1 rw',
    '',
]);
$boot = adapter_validate_boot_log_mount($bootMountinfo);
assert_same('/dev/sda1', $boot['source'], 'The boot log mount must resolve to the independent FAT block device.');
expect_failure(
    static fn() => adapter_validate_boot_log_mount("1 0 0:1 / / rw - rootfs rootfs rw\n"),
    'A root-filesystem /boot fallback must not be accepted as persistent logging.',
);
expect_failure(
    static fn() => adapter_validate_boot_log_mount("36 1 8:1 / /boot rw - ext4 /dev/sda1 rw\n"),
    'A non-FAT /boot mount must not be accepted by the certified Unraid log contract.',
);
expect_failure(
    static fn() => adapter_validate_boot_log_mount("36 1 0:4 / /boot rw - vfat rootfs rw\n"),
    'A non-block-backed /boot mount must fail.',
);
expect_failure(
    static fn() => adapter_validate_boot_log_mount($bootMountinfo."50 36 0:8 / /boot/config rw - tmpfs tmpfs rw\n"),
    'A nested mount shadowing the persistent log directory must fail.',
);
expect_failure(
    static fn() => adapter_validate_boot_log_mount($bootMountinfo."51 36 0:9 / /boot/config/plugins/unassigned.devices/usb-guardian/logs/transactions rw - tmpfs tmpfs rw\n"),
    'A mount nested inside the persistent log directory must fail.',
);
adapter_validate_boot_log_mount($bootMountinfo."52 36 0:10 / /boot/other rw - tmpfs tmpfs rw\n");

$passivePartition = [
    'device' => '/dev/sdb1',
    'mounted' => true,
    'mountpoint' => '/mnt/disks/one',
    'fstype' => 'ext4',
    'shared' => false,
    'command' => '',
    'user_command' => '',
    'enable_script' => false,
];
assert_same([], adapter_configuration_blockers([], [$passivePartition], '', 'disabled'), 'A passive UD configuration must remain eligible.');
foreach ([
    'shared partition' => [[], [array_replace($passivePartition, ['shared' => true])], '', 'disabled'],
    'partition script' => [[], [array_replace($passivePartition, ['command' => '/boot/script.sh'])], '', 'disabled'],
    'manual user script' => [[], [array_replace($passivePartition, ['user_command' => '/boot/user.sh'])], '', 'disabled'],
    'enabled script flag' => [[], [array_replace($passivePartition, ['enable_script' => true])], '', 'disabled'],
    'disk script' => [['command' => '/boot/disk.sh'], [$passivePartition], '', 'disabled'],
    'common script' => [[], [$passivePartition], '/boot/common.sh', 'disabled'],
    'destructive mode' => [[], [$passivePartition], '', 'enabled'],
] as $name => [$disk, $partitions, $common, $destructive]) {
    if (adapter_configuration_blockers($disk, $partitions, $common, $destructive) === []) {
        throw new RuntimeException('Configured UD side effect was not blocked: '.$name);
    }
    expect_failure(
        static fn() => adapter_assert_passive_ud_configuration($disk, $partitions, $common, $destructive),
        'Configured UD side effect must fail closed: '.$name,
    );
}

$inventoryDisk = ['device' => '/dev/sdb', 'partitions' => []];
assert_same('/dev/sdb', adapter_select_disk_from_inventory([$inventoryDisk], 'sdb')['device'], 'The exact UD disk was not selected.');
expect_failure(
    static fn() => adapter_select_disk_from_inventory(false, 'sdb'),
    'A non-array UD inventory must fail explicitly.',
);
expect_failure(
    static fn() => adapter_select_disk_from_inventory([$inventoryDisk, 'malformed'], 'sdb'),
    'A malformed UD inventory entry must fail explicitly.',
);
expect_failure(
    static fn() => adapter_partition_contexts(null),
    'A non-array partitions collection must fail explicitly.',
);
expect_failure(
    static fn() => adapter_partition_contexts([['device' => '/dev/sdb1'], 'malformed']),
    'A malformed partition entry must fail explicitly.',
);

$validPartitions = [
    ['device' => '/dev/sdb1', 'mountpoint' => '/mnt/disks/one', 'mounted' => false],
    ['device' => '/dev/sdb2', 'mountpoint' => '/mnt/disks/two', 'mounted' => false],
];
adapter_validate_partition_ownership('sdb', '/dev/sdb', $validPartitions);
expect_failure(
    static fn() => adapter_validate_partition_ownership('sdb', '/dev/sdc', $validPartitions),
    'A mismatched root disk must fail before the barrier is acquired.',
);
expect_failure(
    static fn() => adapter_validate_partition_ownership('sdb', '/dev/sdb', [['device' => '/dev/sdc1', 'mountpoint' => '/mnt/disks/one']]),
    'A partition outside the target disk must fail.',
);
expect_failure(
    static fn() => adapter_validate_partition_ownership('sdb', '/dev/sdb', [
        ['device' => '/dev/sdb1', 'mountpoint' => '/mnt/disks/one'],
        ['device' => '/dev/sdb1', 'mountpoint' => '/mnt/disks/two'],
    ]),
    'Duplicate partition devices must fail.',
);
expect_failure(
    static fn() => adapter_validate_partition_ownership('sdb', '/dev/sdb', []),
    'An empty target topology must fail.',
);
foreach (['/mnt/disks/../user/share', '/mnt/disks//duplicate', '/mnt/disks/trailing/', "/mnt/disks/control\nname"] as $invalid) {
    expect_failure(static fn() => adapter_validate_mountpoint($invalid, false), 'Unsafe mountpoint accepted: '.$invalid);
}
adapter_validate_mountpoint('/mnt/disks/canonical-name', false);

$kernelMountinfo = "36 29 8:17 / /mnt/disks/one rw,relatime - ext4 /dev/sdb1 rw\n";
adapter_validate_mount_ownership([$passivePartition], $kernelMountinfo, ['/dev/sdb1' => '8:17']);
expect_failure(
    static fn() => adapter_validate_mount_ownership([$passivePartition], "36 29 8:33 / /mnt/disks/one rw - ext4 /dev/sdc1 rw\n", ['/dev/sdb1' => '8:17']),
    'A mountpoint backed by another block device must fail.',
);
adapter_validate_mount_ownership(
    [$passivePartition],
    "36 29 0:42 / /mnt/disks/one rw - fuseblk /dev/sdb1 rw\n",
    ['/dev/sdb1' => '8:17'],
);
expect_failure(
    static fn() => adapter_validate_mount_ownership(
        [$passivePartition],
        "36 29 0:42 / /mnt/disks/one rw - fuseblk /dev/sdc1 rw\n",
        ['/dev/sdb1' => '8:17'],
    ),
    'A FUSE mountpoint whose source is another device must fail.',
);
expect_failure(
    static fn() => adapter_validate_mount_ownership(
        [array_replace($passivePartition, ['mounted' => false])],
        $kernelMountinfo,
        ['/dev/sdb1' => '8:17'],
    ),
    'An allegedly unmounted UD path occupied by a mount must fail.',
);
$snapshot = adapter_target_mount_snapshot([$passivePartition], $kernelMountinfo, ['/dev/sdb1' => '8:17']);
assert_same('/mnt/disks/one', $snapshot[0]['mountpoint'] ?? '', 'Target mount snapshot missed the mounted partition.');
assert_same('36', $snapshot[0]['mount_id'] ?? '', 'The full target mountinfo identity was not retained.');
adapter_validate_target_mount_set([$passivePartition], $snapshot);
expect_failure(
    static fn() => adapter_validate_target_mount_set([$passivePartition], array_merge($snapshot, [[
        'mount_id' => '40', 'parent_id' => '29', 'major_minor' => '8:17', 'root' => '/sub',
        'mountpoint' => '/mnt/disks/extra', 'mount_options' => 'rw', 'optional_fields' => [],
        'fstype' => 'ext4', 'source' => '/dev/sdb1', 'super_options' => 'rw',
    ]])),
    'An extra target mount must fail closed.',
);
$escaped = adapter_parse_mountinfo("36 29 8:17 / /mnt/disks/my\\040disk rw - ext4 /dev/sdb1 rw\n");
assert_same('/mnt/disks/my disk', $escaped[0]['mountpoint'] ?? '', 'Mountinfo escaping was not decoded.');

$template = '/var/state/unassigned.devices/unmounting_%s.state';
$rootMarker = adapter_root_marker_path('sdb', $template);
assert_same('/var/state/unassigned.devices/unmounting_sdb.state', $rootMarker, 'Only the root marker path may be used.');
$conflicts = adapter_target_marker_conflicts_from_paths('sdb', $rootMarker, [
    $rootMarker,
    '/var/state/unassigned.devices/unmounting_sdb1.state',
    '/var/state/unassigned.devices/mounting_sdb2.state',
    '/var/state/unassigned.devices/unmounting_sdc1.state',
]);
assert_same(2, count($conflicts), 'Partition operation markers must be detected while the owned root marker is ignored.');

$token = adapter_marker_token('job-1');
$now = 2000;
adapter_validate_marker_record([
    'exists' => true, 'regular' => true, 'link' => false, 'content' => $token, 'mtime' => $now - 1,
], $token, $now);
expect_failure(
    static fn() => adapter_validate_marker_record([
        'exists' => true, 'regular' => true, 'link' => false, 'content' => 'other', 'mtime' => $now - 1,
    ], $token, $now),
    'A foreign marker token must fail.',
);
expect_failure(
    static fn() => adapter_validate_marker_record([
        'exists' => true, 'regular' => true, 'link' => false, 'content' => $token, 'mtime' => $now - ADAPTER_MARKER_MAX_AGE,
    ], $token, $now),
    'An expired root marker must fail before finalize or rollback.',
);
expect_failure(
    static fn() => adapter_validate_marker_record([
        'exists' => true, 'regular' => true, 'link' => true, 'content' => $token, 'mtime' => $now - 1,
    ], $token, $now),
    'A symlink marker must fail.',
);

$identity = [
    'major_minor' => '8:16',
    'diskseq' => '44',
    'usb_path' => 'devices/pci0000:00/usb1/1-2',
    'usb_vid' => '0781',
    'usb_pid' => '5581',
    'usb_serial' => 'SERIAL-1',
    'usb_busnum' => '1',
    'usb_devnum' => '7',
];
adapter_assert_identity_matches($identity, $identity);
foreach (['major_minor' => '8:32', 'diskseq' => '45', 'usb_path' => 'devices/pci0000:00/usb1/1-3', 'usb_serial' => 'SERIAL-2', 'usb_devnum' => '8'] as $field => $replacement) {
    expect_failure(
        static fn() => adapter_assert_identity_matches($identity, array_replace($identity, [$field => $replacement])),
        'Identity replacement was not detected at '.$field,
    );
}
expect_failure(
    static fn() => adapter_validate_identity_shape(array_diff_key($identity, ['diskseq' => true])),
    'An incomplete identity must fail.',
);

$officialRaceFixture = [
    'in_flight' => "/usr/bin/php\0/usr/local/emhttp/plugins/unassigned.devices/scripts/rc.unassigned\0umount\0/dev/sdb\0",
    'symlink_entry' => "/usr/local/sbin/rc.unassigned\0mount\0/dev/sdb1\0",
    'unrelated' => "/bin/sh\0-c\0echo rc.unassigned\0",
];
assert_same('umount', adapter_certified_rc_process($officialRaceFixture['in_flight'])['action'] ?? '', 'An in-flight certified UD operation was not recognized.');
assert_same('mount', adapter_certified_rc_process($officialRaceFixture['symlink_entry'])['action'] ?? '', 'The certified rc symlink entry was not recognized.');
assert_same(null, adapter_certified_rc_process($officialRaceFixture['unrelated']), 'An unrelated command mentioning rc.unassigned was a false positive.');
assert_same(
    'umount',
    adapter_certified_rc_process("plugins/unassigned.devices/scripts/rc.unassigned\0umount\0/dev/sdb\0", '/usr/local/emhttp')['action'] ?? '',
    'The certified relative emhttp path was not recognized.',
);

$procFixture = sys_get_temp_dir().DIRECTORY_SEPARATOR.'usb-guardian-proc-'.bin2hex(random_bytes(4));
mkdir($procFixture, 0700, true);
mkdir($procFixture.DIRECTORY_SEPARATOR.'4242', 0700, true);
file_put_contents($procFixture.DIRECTORY_SEPARATOR.'4242'.DIRECTORY_SEPARATOR.'cmdline', $officialRaceFixture['in_flight']);
$mutators = adapter_rc_mutators($procFixture);
if (count($mutators) !== 1 || !str_contains($mutators[0], 'pid=4242')) {
    throw new RuntimeException('The proc scanner did not surface the in-flight certified UD process.');
}
mkdir($procFixture.DIRECTORY_SEPARATOR.'4343', 0700, true);
file_put_contents(
    $procFixture.DIRECTORY_SEPARATOR.'4343'.DIRECTORY_SEPARATOR.'cmdline',
    "/usr/bin/php\0/usr/local/emhttp/plugins/unassigned.devices.preclear/scripts/preclear_disk.sh\0--device=/dev/sdb\0",
);
$preclear = adapter_target_preclear_processes('sdb', $procFixture);
if (count($preclear) !== 1 || !str_contains($preclear[0], 'pid=4343')) {
    throw new RuntimeException('The proc scanner did not surface the in-flight target Preclear process.');
}
assert_same([], adapter_target_preclear_processes('sdc', $procFixture), 'A Preclear process for another device was a false positive.');
unlink($procFixture.DIRECTORY_SEPARATOR.'4242'.DIRECTORY_SEPARATOR.'cmdline');
rmdir($procFixture.DIRECTORY_SEPARATOR.'4242');
unlink($procFixture.DIRECTORY_SEPARATOR.'4343'.DIRECTORY_SEPARATOR.'cmdline');
rmdir($procFixture.DIRECTORY_SEPARATOR.'4343');
rmdir($procFixture);

foreach ([
    'execute'.'_script',
    'rm'.'_smb_share',
    'add'.'_smb_share',
    'rm'.'_nfs_share',
    'add'.'_nfs_share',
    'Misc'.'UD',
    'adapter_export'.'_removed',
    'adapter_expected'.'_mounted_state',
] as $forbidden) {
    if (str_contains($source, $forbidden)) {
        throw new RuntimeException('The narrow adapter still contains a forbidden UD side-effect API: '.$forbidden);
    }
}
if (preg_match('/do_unmount\s*\(/', $source) === 1
    || str_contains($source, "'UNMOUNT'")
    || str_contains($source, "'REMOVE'")
    || !str_contains($source, "adapter_effect_log(\$state, 'root_marker_acquire', 'before')")
    || !str_contains($source, "adapter_effect_log(\$state, 'root_marker_release', 'before')")) {
    throw new RuntimeException('The source-level narrow-side-effect contract is not satisfied.');
}

echo "UD adapter narrow barrier contract tests passed.\n";
