#!/usr/bin/php -q
<?php
declare(strict_types=1);

const ADAPTER_SCHEMA_VERSION = 1;
const ADAPTER_UD_LIB = '/usr/local/emhttp/plugins/unassigned.devices/include/lib.php';
const ADAPTER_RUN_DIR = '/run/ud-usb-guardian';
const ADAPTER_STATE_DIR = ADAPTER_RUN_DIR.'/ud-adapter';
const ADAPTER_LOG_DIR = '/boot/config/plugins/unassigned.devices/usb-guardian/logs';
const ADAPTER_LOG_FILE = ADAPTER_LOG_DIR.'/ud-adapter.log';
const ADAPTER_MARKER_MAX_AGE = 240;
const ADAPTER_BARRIER_STABLE_US = 600000;
const ADAPTER_BARRIER_TIMEOUT_US = 12000000;

ini_set('display_errors', '0');
error_reporting(E_ALL);

function adapter_json(array $payload): void
{
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)."\n";
    exit(0);
}

function adapter_read_bounded_file(string $path, int $limit): string
{
    $handle = @fopen($path, 'rb');
    if (!is_resource($handle)) {
        throw new RuntimeException('Unable to read required runtime file: '.$path);
    }
    $contents = @stream_get_contents($handle, $limit + 1);
    @fclose($handle);
    if (!is_string($contents) || strlen($contents) > $limit) {
        throw new RuntimeException('Required runtime file is unreadable or unexpectedly large: '.$path);
    }
    return $contents;
}

function adapter_path_within(string $path, string $base): bool
{
    $path = rtrim(str_replace('\\', '/', $path), '/');
    $base = rtrim(str_replace('\\', '/', $base), '/');
    return $path === $base || ($base !== '' && str_starts_with($path, $base.'/'));
}

function adapter_mountinfo_unescape(string $value): string
{
    return str_replace(
        ['\\040', '\\011', '\\012', '\\134'],
        [' ', "\t", "\n", '\\'],
        $value,
    );
}

function adapter_parse_mountinfo(string $contents): array
{
    if (strlen($contents) > 4 * 1024 * 1024) {
        throw new RuntimeException('The current mount table is unexpectedly large.');
    }
    $mounts = [];
    foreach (preg_split('/\r?\n/', $contents) ?: [] as $line) {
        if ($line === '') {
            continue;
        }
        $halves = explode(' - ', $line, 2);
        $left = preg_split('/ +/', trim($halves[0] ?? '')) ?: [];
        $right = preg_split('/ +/', trim($halves[1] ?? '')) ?: [];
        if (count($halves) !== 2
            || count($left) < 6
            || count($right) < 3
            || preg_match('/\A[0-9]+\z/', $left[0]) !== 1
            || preg_match('/\A[0-9]+\z/', $left[1]) !== 1
            || preg_match('/\A[0-9]+:[0-9]+\z/', $left[2]) !== 1) {
            throw new RuntimeException('The current mount table contains an unparseable entry.');
        }
        $mounts[] = [
            'mount_id' => $left[0],
            'parent_id' => $left[1],
            'major_minor' => $left[2],
            'root' => adapter_mountinfo_unescape($left[3]),
            'mountpoint' => adapter_mountinfo_unescape($left[4]),
            'mount_options' => $left[5],
            'optional_fields' => array_slice($left, 6),
            'fstype' => strtolower($right[0]),
            'source' => adapter_mountinfo_unescape($right[1]),
            'super_options' => implode(' ', array_slice($right, 2)),
        ];
    }
    return $mounts;
}

function adapter_validate_boot_log_mount(string $mountinfoContents, string $logDirectory = ADAPTER_LOG_DIR): array
{
    $mounts = adapter_parse_mountinfo($mountinfoContents);
    $boot = array_values(array_filter(
        $mounts,
        static fn(array $mount): bool => ($mount['mountpoint'] ?? '') === '/boot',
    ));
    if (count($boot) !== 1) {
        throw new RuntimeException('Persistent logging requires exactly one independent /boot mount.');
    }
    $record = $boot[0];
    [$major] = array_pad(explode(':', (string)$record['major_minor'], 2), 2, '0');
    if (!in_array((string)$record['fstype'], ['vfat', 'msdos'], true)
        || (string)$record['root'] !== '/'
        || !str_starts_with((string)$record['source'], '/dev/')
        || (int)$major <= 0) {
        throw new RuntimeException('Persistent logging requires /boot to be a block-backed vfat/msdos mount.');
    }
    foreach ($mounts as $mount) {
        $mountpoint = (string)($mount['mountpoint'] ?? '');
        if ($mountpoint !== '/boot'
            && str_starts_with($mountpoint, '/boot/')
            && (adapter_path_within($logDirectory, $mountpoint) || adapter_path_within($mountpoint, $logDirectory))) {
            throw new RuntimeException('Persistent log directory overlaps a nested mount: '.$mountpoint);
        }
    }
    return $record;
}

function adapter_log(string $event, array $context = []): bool
{
    try {
        $mountinfo = adapter_read_bounded_file('/proc/self/mountinfo', 4 * 1024 * 1024);
        adapter_validate_boot_log_mount($mountinfo);
    } catch (Throwable) {
        return false;
    }
    if (!is_dir(ADAPTER_LOG_DIR) && !@mkdir(ADAPTER_LOG_DIR, 0700, true) && !is_dir(ADAPTER_LOG_DIR)) {
        return false;
    }
    if (!is_dir(ADAPTER_RUN_DIR) && !@mkdir(ADAPTER_RUN_DIR, 0700, true) && !is_dir(ADAPTER_RUN_DIR)) {
        return false;
    }
    $lock = @fopen(ADAPTER_RUN_DIR.'/flat-log.lock', 'c+');
    if (!is_resource($lock) || !@flock($lock, LOCK_EX)) {
        if (is_resource($lock)) {
            @fclose($lock);
        }
        return false;
    }
    if (is_file(ADAPTER_LOG_FILE) && (int)@filesize(ADAPTER_LOG_FILE) >= 1048576) {
        @unlink(ADAPTER_LOG_FILE.'.2');
        if (is_file(ADAPTER_LOG_FILE.'.1')) {
            @rename(ADAPTER_LOG_FILE.'.1', ADAPTER_LOG_FILE.'.2');
        }
        @rename(ADAPTER_LOG_FILE, ADAPTER_LOG_FILE.'.1');
    }
    $record = ['timestamp' => gmdate('c'), 'event' => $event] + $context;
    $encoded = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    if (!is_string($encoded)) {
        @flock($lock, LOCK_UN);
        @fclose($lock);
        return false;
    }
    if ((file_exists(ADAPTER_LOG_FILE) || is_link(ADAPTER_LOG_FILE))
        && (!is_file(ADAPTER_LOG_FILE) || is_link(ADAPTER_LOG_FILE))) {
        @flock($lock, LOCK_UN);
        @fclose($lock);
        return false;
    }
    $handle = @fopen(ADAPTER_LOG_FILE, 'ab');
    $line = $encoded."\n";
    $written = false;
    if (is_resource($handle) && @flock($handle, LOCK_EX)) {
        $status = @fstat($handle);
        $written = is_array($status)
            && (($status['mode'] ?? 0) & 0170000) === 0100000
            && @fwrite($handle, $line) === strlen($line)
            && @fflush($handle)
            && function_exists('fsync')
            && @fsync($handle);
        @chmod(ADAPTER_LOG_FILE, 0600);
        @flock($handle, LOCK_UN);
    }
    if (is_resource($handle)) {
        @fclose($handle);
    }
    @flock($lock, LOCK_UN);
    @fclose($lock);
    return $written;
}

function adapter_require_effect_log(string $event, array $context): void
{
    if (!adapter_log($event, $context)) {
        throw new RuntimeException('Unable to durably record the UD barrier side effect; no further side effect is allowed.');
    }
}

function adapter_effect_log(array $state, string $effect, string $moment, array $context = []): void
{
    adapter_require_effect_log('side_effect_'.$moment, [
        'job_id' => (string)($state['job_id'] ?? ''),
        'kernel_name' => (string)($state['kernel_name'] ?? ''),
        'phase' => (string)($state['phase'] ?? ''),
        'effect' => $effect,
        'result' => (string)($context['result'] ?? ''),
        'error' => (string)($context['error'] ?? ''),
    ]);
}

function adapter_fail(string $message, array $details = [], bool $supported = true): void
{
    $shouldLog = ($GLOBALS['adapter_action'] ?? '') !== 'inspect';
    if (!$shouldLog) {
        if (!is_dir(ADAPTER_RUN_DIR)) {
            @mkdir(ADAPTER_RUN_DIR, 0700, true);
        }
        $signature = hash('sha256', $message.'|'.json_encode($details, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
        $marker = ADAPTER_RUN_DIR.'/inspect-error.sha256';
        if ((string)@file_get_contents($marker) !== $signature) {
            @file_put_contents($marker, $signature, LOCK_EX);
            @chmod($marker, 0600);
            $shouldLog = true;
        }
    }
    if ($shouldLog) {
        adapter_log('adapter_failed', ['message' => $message, 'details' => $details]);
    }
    adapter_json([
        'schema_version' => ADAPTER_SCHEMA_VERSION,
        'ok' => false,
        'supported' => $supported,
        'error' => $message,
        'message' => $message,
        'version' => (string)($details['version'] ?? ''),
        'details' => $details,
    ]);
}

function adapter_truthy(mixed $value): bool
{
    return $value === true || $value === 1 || in_array(strtolower((string)$value), ['1', 'yes', 'true', 'on'], true);
}

function adapter_require_supported_ud(): array
{
    if (!is_file(ADAPTER_UD_LIB)) {
        adapter_fail('Unassigned Devices library is unavailable.', [], false);
    }
    return ['edition' => 'official', 'version' => 'native'];
}

function adapter_ud_runtime_capability_error(): string
{
    global $cfg, $paths;
    foreach (['get_all_disks_info', 'get_config'] as $function) {
        if (!function_exists($function)) {
            return "Required read-only Unassigned Devices API is unavailable: {$function}";
        }
    }
    if (!defined('UD_CONFIG_FILE') || !is_array($cfg ?? null)) {
        return 'The Unassigned Devices runtime configuration API is unavailable.';
    }
    if (!is_array($paths ?? null)
        || ($paths['unmounting'] ?? '') !== '/var/state/unassigned.devices/unmounting_%s.state') {
        return 'The Unassigned Devices operation-barrier API is unavailable.';
    }
    return '';
}

function adapter_find_disk(string $kernelName): array
{
    global $mounts, $lsblk_file_types;
    $mounts = null;
    $lsblk_file_types = null;
    adapter_refresh_ud_config_cache();
    return adapter_select_disk_from_inventory(get_all_disks_info(), $kernelName);
}

function adapter_refresh_ud_config_cache(): void
{
    global $cfg, $ud_config;
    if (!defined('UD_CONFIG_FILE') || !is_file(UD_CONFIG_FILE) || is_link(UD_CONFIG_FILE)) {
        throw new RuntimeException('The compatible Unassigned Devices runtime configuration is unavailable or unsafe.');
    }
    $parsed = @parse_ini_file(UD_CONFIG_FILE, true, INI_SCANNER_RAW);
    if (!is_array($parsed) || !is_array($cfg ?? null)) {
        throw new RuntimeException('The compatible Unassigned Devices runtime configuration cannot be refreshed.');
    }
    $ud_config = array_replace_recursive($cfg, $parsed);
}

function adapter_select_disk_from_inventory(mixed $inventory, string $kernelName): array
{
    if (!is_array($inventory)) {
        throw new RuntimeException('Unassigned Devices returned a malformed disk inventory.');
    }
    $matches = [];
    foreach ($inventory as $disk) {
        if (!is_array($disk)) {
            throw new RuntimeException('Unassigned Devices disk inventory contains a malformed entry.');
        }
        if (basename((string)($disk['device'] ?? '')) === $kernelName) {
            $matches[] = $disk;
        }
    }
    if (count($matches) !== 1) {
        throw new RuntimeException(count($matches) === 0
            ? "Device {$kernelName} is not owned by Unassigned Devices."
            : "Device {$kernelName} is ambiguous in Unassigned Devices state.");
    }
    return $matches[0];
}

function adapter_scalar_string(mixed $value): string
{
    return is_scalar($value) || $value === null ? trim((string)$value) : '';
}

function adapter_validate_mountpoint(string $mountpoint, bool $mounted): void
{
    if ($mountpoint === '') {
        if ($mounted) {
            throw new RuntimeException('Mounted UD partition has no mountpoint.');
        }
        return;
    }
    $name = basename($mountpoint);
    if (preg_match('/[\x00-\x1f\x7f]/', $mountpoint) === 1
        || $name === '' || $name === '.' || $name === '..'
        || dirname($mountpoint) !== '/mnt/disks'
        || $mountpoint !== '/mnt/disks/'.$name) {
        throw new RuntimeException('UD partition mountpoint is not a canonical single-level /mnt/disks path: '.$mountpoint);
    }
    if ($mounted) {
        $resolved = realpath($mountpoint);
        if (is_link($mountpoint) || $resolved === false || $resolved !== $mountpoint) {
            throw new RuntimeException('Mounted UD partition mountpoint is a symlink or does not resolve to itself: '.$mountpoint);
        }
    }
}

function adapter_partition_context(array $partition): array
{
    $fstype = strtolower((string)($partition['fstype'] ?? ($partition['file_system'] ?? '')));
    $mountpoint = (string)($partition['mountpoint'] ?? '');
    $mounted = adapter_truthy($partition['mounted'] ?? false);
    adapter_validate_mountpoint($mountpoint, $mounted);
    if (in_array($fstype, ['zfs', 'crypto_luks'], true)
        || adapter_scalar_string($partition['luks'] ?? '') !== ''
        || adapter_truthy($partition['pool'] ?? false)) {
        throw new RuntimeException('ZFS, LUKS, and UD pool devices are not supported by this adapter.');
    }
    return [
        'device' => adapter_scalar_string($partition['device'] ?? ''),
        'serial' => adapter_scalar_string($partition['serial'] ?? ''),
        'mounted' => $mounted,
        'mountpoint' => $mountpoint,
        'fstype' => $fstype,
        'shared' => adapter_truthy($partition['shared'] ?? false),
        'command' => adapter_scalar_string($partition['command'] ?? ''),
        'user_command' => adapter_scalar_string($partition['user_command'] ?? ''),
        'enable_script' => adapter_truthy($partition['enable_script'] ?? false),
    ];
}

function adapter_configuration_blockers(array $disk, array $partitions, string $commonCommand, string $destructiveMode = ''): array
{
    $blockers = [];
    if (trim($commonCommand) !== '') {
        $blockers[] = 'a Common Script is configured';
    }
    if (strtolower(trim($destructiveMode)) === 'enabled' || adapter_truthy($destructiveMode)) {
        $blockers[] = 'UD destructive mode is enabled';
    }
    foreach ([['label' => 'disk', 'value' => $disk], ...array_map(
        static fn(array $partition): array => ['label' => (string)($partition['device'] ?? 'partition'), 'value' => $partition],
        $partitions,
    )] as $item) {
        $value = $item['value'];
        $label = $item['label'];
        if ($label !== 'disk' && adapter_truthy($value['shared'] ?? false)) {
            $blockers[] = $label.' has sharing enabled';
        }
        if (adapter_scalar_string($value['command'] ?? '') !== ''
            || adapter_scalar_string($value['user_command'] ?? '') !== ''
            || adapter_truthy($value['enable_script'] ?? false)) {
            $blockers[] = $label.' has a device or user script configured';
        }
    }
    return array_values(array_unique($blockers));
}

function adapter_assert_passive_ud_configuration(array $disk, array $partitions, string $commonCommand, string $destructiveMode = ''): void
{
    $blockers = adapter_configuration_blockers($disk, $partitions, $commonCommand, $destructiveMode);
    if (!$blockers) {
        return;
    }
    throw new RuntimeException(
        'Strict Beta mode cannot eject while Unassigned Devices sharing, scripts, or destructive mode are configured: '
        .implode('; ', array_slice($blockers, 0, 6))
        .'. Disable Share for every target partition, clear the target Device Script/User Script and Common Script settings, '
        .'turn off UD Destructive Mode, disconnect SMB/NFS clients, wait for running scripts to stop, then retry.',
    );
}

function adapter_partition_contexts(mixed $rawPartitions): array
{
    if (!is_array($rawPartitions)) {
        throw new RuntimeException('Unassigned Devices returned a malformed partitions collection.');
    }
    $partitions = [];
    foreach ($rawPartitions as $partition) {
        if (!is_array($partition)) {
            throw new RuntimeException('Unassigned Devices returned a malformed partition entry.');
        }
        $partitions[] = adapter_partition_context($partition);
    }
    return $partitions;
}

function adapter_validate_partition_ownership(string $kernelName, string $diskDevice, array $partitions): void
{
    if ($diskDevice !== '/dev/'.$kernelName) {
        throw new RuntimeException('UD disk identity does not match the requested kernel device.');
    }
    if (!$partitions) {
        throw new RuntimeException('UD returned no target partition or whole-disk filesystem record.');
    }
    $devices = [];
    $mountpoints = [];
    $expectedDevice = '#\A/dev/'.preg_quote($kernelName, '#').'(?:[0-9]+)?\z#';
    foreach ($partitions as $partition) {
        $device = (string)($partition['device'] ?? '');
        $mountpoint = (string)($partition['mountpoint'] ?? '');
        adapter_validate_mountpoint($mountpoint, ($partition['mounted'] ?? false) === true);
        if ($device === '' || preg_match($expectedDevice, $device) !== 1 || isset($devices[$device])) {
            throw new RuntimeException('UD partition ownership is missing, duplicated, or outside the requested disk.');
        }
        $devices[$device] = true;
        if ($mountpoint !== '') {
            if (isset($mountpoints[$mountpoint])) {
                throw new RuntimeException('UD partition mountpoint is duplicated.');
            }
            $mountpoints[$mountpoint] = true;
        }
    }
}

function adapter_partition_device_numbers(array $partitions, string $sysRoot = '/sys'): array
{
    $numbers = [];
    foreach ($partitions as $partition) {
        $device = (string)($partition['device'] ?? '');
        $name = basename($device);
        $number = trim((string)@file_get_contents(rtrim($sysRoot, '/').'/class/block/'.$name.'/dev'));
        if ($device === '' || preg_match('/\A[0-9]+:[0-9]+\z/', $number) !== 1) {
            throw new RuntimeException('The block-device number cannot be verified for '.$device);
        }
        $numbers[$device] = $number;
    }
    return $numbers;
}

function adapter_fuse_source_matches(string $source, string $device): bool
{
    if ($source === $device) {
        return true;
    }
    $sourceReal = realpath($source);
    $deviceReal = realpath($device);
    return $sourceReal !== false && $deviceReal !== false && $sourceReal === $deviceReal;
}

function adapter_validate_mount_ownership(array $partitions, ?string $mountinfoContents = null, ?array $deviceNumbers = null): void
{
    $mountinfoContents ??= adapter_read_bounded_file('/proc/self/mountinfo', 4 * 1024 * 1024);
    $mounts = adapter_parse_mountinfo($mountinfoContents);
    $deviceNumbers ??= adapter_partition_device_numbers($partitions);
    foreach ($partitions as $partition) {
        $device = (string)($partition['device'] ?? '');
        $mountpoint = (string)($partition['mountpoint'] ?? '');
        $mounted = ($partition['mounted'] ?? false) === true;
        if ($mountpoint === '') {
            if ($mounted) {
                throw new RuntimeException('A mounted UD partition has no mountpoint ownership record.');
            }
            continue;
        }
        $matches = array_values(array_filter($mounts, static fn(array $mount): bool => ($mount['mountpoint'] ?? '') === $mountpoint));
        if (!$mounted) {
            if ($matches) {
                throw new RuntimeException('UD reports an unmounted partition but its mountpoint is occupied: '.$mountpoint);
            }
            continue;
        }
        if (count($matches) !== 1) {
            throw new RuntimeException('A mounted UD partition does not have exactly one mount table entry: '.$mountpoint);
        }
        $number = (string)($deviceNumbers[$device] ?? '');
        $mount = $matches[0];
        $fuseMatches = str_starts_with((string)$mount['fstype'], 'fuse')
            && adapter_fuse_source_matches((string)$mount['source'], $device);
        if ((string)$mount['major_minor'] !== $number && !$fuseMatches) {
            throw new RuntimeException(
                'UD mountpoint ownership does not match its partition: '.$mountpoint
                .' expected='.$number.' observed='.(string)$mount['major_minor'].' source='.(string)$mount['source'],
            );
        }
    }
}

function adapter_target_mount_snapshot(array $partitions, ?string $mountinfoContents = null, ?array $deviceNumbers = null): array
{
    $mountinfoContents ??= adapter_read_bounded_file('/proc/self/mountinfo', 4 * 1024 * 1024);
    $mounts = adapter_parse_mountinfo($mountinfoContents);
    $deviceNumbers ??= adapter_partition_device_numbers($partitions);
    $byNumber = array_flip(array_values($deviceNumbers));
    $devices = array_keys($deviceNumbers);
    $snapshot = [];
    foreach ($mounts as $mount) {
        $matches = isset($byNumber[(string)$mount['major_minor']]);
        if (!$matches && str_starts_with((string)$mount['fstype'], 'fuse')) {
            foreach ($devices as $device) {
                if (adapter_fuse_source_matches((string)$mount['source'], $device)) {
                    $matches = true;
                    break;
                }
            }
        }
        if ($matches) {
            $snapshot[] = [
                'mount_id' => (string)$mount['mount_id'],
                'parent_id' => (string)$mount['parent_id'],
                'major_minor' => (string)$mount['major_minor'],
                'root' => (string)$mount['root'],
                'mountpoint' => (string)$mount['mountpoint'],
                'mount_options' => (string)$mount['mount_options'],
                'optional_fields' => $mount['optional_fields'],
                'fstype' => (string)$mount['fstype'],
                'source' => (string)$mount['source'],
                'super_options' => (string)$mount['super_options'],
            ];
        }
    }
    usort($snapshot, static fn(array $a, array $b): int => strcmp(serialize($a), serialize($b)));
    return $snapshot;
}

function adapter_validate_target_mount_set(array $partitions, array $snapshot): void
{
    $expected = [];
    foreach ($partitions as $partition) {
        if (($partition['mounted'] ?? false) === true) {
            $expected[] = (string)$partition['mountpoint'];
        }
    }
    $observed = array_map(static fn(array $mount): string => (string)$mount['mountpoint'], $snapshot);
    sort($expected, SORT_STRING);
    sort($observed, SORT_STRING);
    if ($expected !== $observed) {
        throw new RuntimeException('The active target mount set does not exactly match Unassigned Devices state.');
    }
}

function adapter_inspect_device(string $kernelName, bool $ownedRootMarker = false): array
{
    $disk = adapter_find_disk($kernelName);
    if (adapter_truthy($disk['array_disk'] ?? false)
        || adapter_truthy($disk['pass_through'] ?? false)
        || adapter_truthy($disk['pool_disk'] ?? false)) {
        throw new RuntimeException('Unassigned Devices reports this disk as an array, pool, or pass-through device.');
    }
    if (!empty($disk['zvol'])) {
        throw new RuntimeException('UD ZFS volume devices are not supported by this adapter.');
    }
    foreach (['mounting', 'unmounting', 'formatting', 'clearing', 'running', 'preclearing'] as $field) {
        if (adapter_truthy($disk[$field] ?? false) && !($ownedRootMarker && $field === 'unmounting')) {
            throw new RuntimeException("Unassigned Devices reports {$kernelName} is currently {$field}.");
        }
    }
    $rawPartitions = $disk['partitions'] ?? null;
    $partitions = adapter_partition_contexts($rawPartitions);
    foreach ($rawPartitions as $index => $partition) {
        foreach (['mounting', 'unmounting', 'formatting', 'clearing', 'running', 'preclearing'] as $field) {
            if (adapter_truthy($partition[$field] ?? false) && !($ownedRootMarker && $field === 'unmounting')) {
                throw new RuntimeException("Unassigned Devices reports a {$kernelName} partition is currently {$field}.");
            }
        }
    }
    $commonCommand = adapter_scalar_string(get_config('Config', 'common_cmd'));
    $destructiveMode = adapter_scalar_string(get_config('Config', 'destructive_mode'));
    adapter_assert_passive_ud_configuration($disk, $partitions, $commonCommand, $destructiveMode);
    $diskDevice = (string)($disk['device'] ?? '');
    adapter_validate_partition_ownership($kernelName, $diskDevice, $partitions);
    $mountinfo = adapter_read_bounded_file('/proc/self/mountinfo', 4 * 1024 * 1024);
    $numbers = adapter_partition_device_numbers($partitions);
    adapter_validate_mount_ownership($partitions, $mountinfo, $numbers);
    $mountSnapshot = adapter_target_mount_snapshot($partitions, $mountinfo, $numbers);
    adapter_validate_target_mount_set($partitions, $mountSnapshot);
    return ['device' => $diskDevice, 'partitions' => $partitions, 'mount_snapshot' => $mountSnapshot];
}

function adapter_identity_keys(): array
{
    return ['major_minor', 'diskseq', 'usb_path', 'usb_vid', 'usb_pid', 'usb_serial', 'usb_busnum', 'usb_devnum'];
}

function adapter_validate_identity_shape(array $identity): void
{
    foreach (adapter_identity_keys() as $key) {
        if (!array_key_exists($key, $identity) || !is_string($identity[$key])) {
            throw new RuntimeException('USB identity snapshot is incomplete: '.$key);
        }
    }
    if (preg_match('/\A[0-9]+:[0-9]+\z/', $identity['major_minor']) !== 1
        || preg_match('/\A[0-9]+\z/', $identity['diskseq']) !== 1
        || preg_match('/\A[0-9a-fA-F]{4}\z/', $identity['usb_vid']) !== 1
        || preg_match('/\A[0-9a-fA-F]{4}\z/', $identity['usb_pid']) !== 1
        || preg_match('/\A[0-9]+\z/', $identity['usb_busnum']) !== 1
        || preg_match('/\A[0-9]+\z/', $identity['usb_devnum']) !== 1
        || (int)$identity['usb_busnum'] <= 0
        || (int)$identity['usb_devnum'] <= 0
        || !str_starts_with($identity['usb_path'], 'devices/')
        || str_contains($identity['usb_path'], '..')
        || preg_match('/[\x00-\x1f\x7f]/', $identity['usb_path'].$identity['usb_serial']) === 1) {
        throw new RuntimeException('USB identity snapshot contains an invalid or unavailable field.');
    }
}

function adapter_device_identity(string $kernelName, string $sysRoot = '/sys'): array
{
    $root = realpath($sysRoot);
    $class = realpath(rtrim($sysRoot, '/').'/class/block/'.$kernelName);
    if ($root === false || $class === false || !adapter_path_within($class, $root)) {
        throw new RuntimeException('The target block device sysfs identity cannot be resolved.');
    }
    $usb = '';
    $cursor = $class;
    for ($depth = 0; $depth < 40 && adapter_path_within($cursor, $root); $depth++) {
        $uevent = (string)@file_get_contents($cursor.'/uevent');
        if (str_contains($uevent, "DEVTYPE=usb_device\n")
            || (is_file($cursor.'/idVendor') && is_file($cursor.'/idProduct'))) {
            $usb = $cursor;
            break;
        }
        $parent = dirname($cursor);
        if ($parent === $cursor) {
            break;
        }
        $cursor = $parent;
    }
    if ($usb === '') {
        throw new RuntimeException('The physical USB sysfs ancestor cannot be verified.');
    }
    $relative = ltrim(str_replace('\\', '/', substr($usb, strlen(rtrim($root, DIRECTORY_SEPARATOR)))), '/');
    $read = static fn(string $path): string => trim((string)@file_get_contents($path));
    $identity = [
        'major_minor' => $read(rtrim($sysRoot, '/').'/class/block/'.$kernelName.'/dev'),
        'diskseq' => $read(rtrim($sysRoot, '/').'/class/block/'.$kernelName.'/diskseq'),
        'usb_path' => $relative,
        'usb_vid' => strtolower($read($usb.'/idVendor')),
        'usb_pid' => strtolower($read($usb.'/idProduct')),
        'usb_serial' => $read($usb.'/serial'),
        'usb_busnum' => $read($usb.'/busnum'),
        'usb_devnum' => $read($usb.'/devnum'),
    ];
    adapter_validate_identity_shape($identity);
    return $identity;
}

function adapter_assert_identity_matches(array $expected, array $current): void
{
    adapter_validate_identity_shape($expected);
    adapter_validate_identity_shape($current);
    foreach (adapter_identity_keys() as $key) {
        if ($expected[$key] !== $current[$key]) {
            throw new RuntimeException('Target USB identity changed at '.$key.'. Keep both devices connected and collect diagnostics.');
        }
    }
}

function adapter_topology_snapshot(array $inspection): array
{
    $partitions = [];
    foreach ($inspection['partitions'] as $partition) {
        $partitions[] = [
            'device' => (string)$partition['device'],
            'mounted' => ($partition['mounted'] ?? false) === true,
            'mountpoint' => (string)$partition['mountpoint'],
            'fstype' => (string)$partition['fstype'],
        ];
    }
    usort($partitions, static fn(array $a, array $b): int => strcmp($a['device'], $b['device']));
    return ['device' => (string)$inspection['device'], 'partitions' => $partitions];
}

function adapter_topology_without_mount_state(array $topology): array
{
    foreach ($topology['partitions'] as &$partition) {
        unset($partition['mounted']);
    }
    unset($partition);
    return $topology;
}

function adapter_state_path(string $jobId): string
{
    if (preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/', $jobId) !== 1) {
        throw new InvalidArgumentException('Invalid job identifier.');
    }
    return ADAPTER_STATE_DIR.'/'.$jobId.'.json';
}

function adapter_write_state(string $path, array $state): void
{
    if (!is_dir(ADAPTER_STATE_DIR) && !@mkdir(ADAPTER_STATE_DIR, 0700, true) && !is_dir(ADAPTER_STATE_DIR)) {
        throw new RuntimeException('Unable to create UD adapter state directory.');
    }
    $encoded = json_encode($state, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)."\n";
    if (!is_string($encoded)) {
        throw new RuntimeException('Unable to encode UD adapter rollback state.');
    }
    $temporary = $path.'.tmp.'.bin2hex(random_bytes(6));
    if (@file_put_contents($temporary, $encoded, LOCK_EX) !== strlen($encoded)) {
        @unlink($temporary);
        throw new RuntimeException('Unable to write UD adapter rollback state.');
    }
    @chmod($temporary, 0600);
    $handle = @fopen($temporary, 'r+b');
    if (!is_resource($handle) || !@fflush($handle) || (function_exists('fsync') && !@fsync($handle))) {
        if (is_resource($handle)) {
            @fclose($handle);
        }
        @unlink($temporary);
        throw new RuntimeException('Unable to synchronize UD adapter rollback state.');
    }
    @fclose($handle);
    if (!@rename($temporary, $path)) {
        @unlink($temporary);
        throw new RuntimeException('Unable to activate UD adapter rollback state.');
    }
}

function adapter_marker_token(string $jobId): string
{
    return 'usb.guardian:'.$jobId."\n";
}

function adapter_root_marker_path(string $kernelName, ?string $template = null): string
{
    if ($template === null) {
        global $paths;
        $template = is_array($paths ?? null) ? (string)($paths['unmounting'] ?? '') : '';
    }
    if ($template !== '/var/state/unassigned.devices/unmounting_%s.state') {
        throw new RuntimeException('The compatible UD unmounting-state path convention is unavailable.');
    }
    if (preg_match('/\Asd[a-z]+\z/', $kernelName) !== 1) {
        throw new RuntimeException('Unsupported root marker device name.');
    }
    return sprintf($template, $kernelName);
}

function adapter_validate_state_shape(array $state, string $jobId, string $kernelName, array $ud): void
{
    if (($state['schema_version'] ?? null) !== ADAPTER_SCHEMA_VERSION
        || ($state['job_id'] ?? '') !== $jobId
        || ($state['kernel_name'] ?? '') !== $kernelName
        || ($state['device'] ?? '') !== '/dev/'.$kernelName
        || ($state['edition'] ?? '') !== $ud['edition']
        || ($state['version'] ?? '') !== $ud['version']
        || ($state['marker_token'] ?? '') !== adapter_marker_token($jobId)
        || ($state['operation_markers'] ?? null) !== [adapter_root_marker_path($kernelName)]
        || !is_array($state['partitions'] ?? null)
        || !is_array($state['topology'] ?? null)
        || !is_array($state['mount_snapshot'] ?? null)
        || preg_match('/\A[a-z][a-z0-9_]{0,63}\z/', (string)($state['phase'] ?? '')) !== 1) {
        throw new RuntimeException('UD adapter rollback state failed identity or schema validation.');
    }
    adapter_validate_identity_shape(is_array($state['identity'] ?? null) ? $state['identity'] : []);
}

function adapter_read_state(string $path, string $kernelName, array $ud, string $jobId): array
{
    $status = @lstat($path);
    if (!is_array($status)
        || (($status['mode'] ?? 0) & 0170000) !== 0100000
        || is_link($path)
        || (int)($status['size'] ?? 0) <= 0
        || (int)$status['size'] > 2 * 1024 * 1024) {
        throw new RuntimeException('UD adapter rollback state is missing, unsafe, or unexpectedly large.');
    }
    $state = json_decode(adapter_read_bounded_file($path, 2 * 1024 * 1024), true);
    if (!is_array($state)) {
        throw new RuntimeException('UD adapter rollback state is not valid JSON.');
    }
    adapter_validate_state_shape($state, $jobId, $kernelName, $ud);
    return $state;
}

function adapter_failure_phase(string $jobId, string $kernelName): string
{
    if (preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/', $jobId) !== 1
        || preg_match('/\Asd[a-z]+\z/', $kernelName) !== 1) {
        return '';
    }
    $path = ADAPTER_STATE_DIR.'/'.$jobId.'.json';
    $status = @lstat($path);
    if (!is_array($status) || (($status['mode'] ?? 0) & 0170000) !== 0100000 || is_link($path)
        || (int)($status['size'] ?? 0) <= 0 || (int)$status['size'] > 2 * 1024 * 1024) {
        return '';
    }
    try {
        $state = json_decode(adapter_read_bounded_file($path, 2 * 1024 * 1024), true);
    } catch (Throwable) {
        return '';
    }
    if (!is_array($state) || ($state['job_id'] ?? '') !== $jobId || ($state['kernel_name'] ?? '') !== $kernelName) {
        return '';
    }
    $phase = (string)($state['phase'] ?? '');
    return preg_match('/\A[a-z][a-z0-9_]{0,63}\z/', $phase) === 1 ? $phase : '';
}

function adapter_marker_record(string $path): array
{
    $status = @lstat($path);
    if (!is_array($status)) {
        return ['exists' => false, 'regular' => false, 'link' => false, 'content' => '', 'mtime' => 0];
    }
    $content = '';
    try {
        $content = adapter_read_bounded_file($path, 512);
    } catch (Throwable) {
    }
    return [
        'exists' => true,
        'regular' => (($status['mode'] ?? 0) & 0170000) === 0100000,
        'link' => is_link($path),
        'content' => $content,
        'mtime' => (int)($status['mtime'] ?? 0),
    ];
}

function adapter_validate_marker_record(array $record, string $token, int $now): void
{
    $age = $now - (int)($record['mtime'] ?? 0);
    if (($record['exists'] ?? false) !== true
        || ($record['regular'] ?? false) !== true
        || ($record['link'] ?? false) === true
        || (string)($record['content'] ?? '') !== $token) {
        throw new RuntimeException('UD root operation marker ownership was lost.');
    }
    if ($age < -5 || $age >= ADAPTER_MARKER_MAX_AGE) {
        throw new RuntimeException('UD root operation marker is too old or has an invalid timestamp; reboot normally with the device connected.');
    }
}

function adapter_assert_owned_root_marker(array $state): void
{
    $path = adapter_root_marker_path((string)$state['kernel_name']);
    adapter_validate_marker_record(adapter_marker_record($path), (string)$state['marker_token'], time());
}

function adapter_target_marker_conflicts_from_paths(string $kernelName, string $ownedRootMarker, array $markerPaths): array
{
    $conflicts = [];
    $pattern = '/\A(?:mounting|unmounting|formatting|clearing)_'.preg_quote($kernelName, '/').'(?:[0-9]+)?\.state\z/';
    foreach ($markerPaths as $path) {
        if (!is_string($path) || preg_match($pattern, basename($path)) !== 1) {
            continue;
        }
        if ($path !== $ownedRootMarker) {
            $conflicts[] = $path;
        }
    }
    return array_values(array_unique($conflicts));
}

function adapter_runtime_operation_markers(): array
{
    $markers = [];
    foreach (['mounting', 'unmounting', 'formatting', 'clearing'] as $operation) {
        foreach (glob('/var/state/unassigned.devices/'.$operation.'_*.state') ?: [] as $path) {
            $markers[] = $path;
        }
    }
    return array_values(array_unique($markers));
}

function adapter_assert_target_markers_quiet(array $state): void
{
    $owned = adapter_root_marker_path((string)$state['kernel_name']);
    $conflicts = adapter_target_marker_conflicts_from_paths((string)$state['kernel_name'], $owned, adapter_runtime_operation_markers());
    if ($conflicts) {
        throw new RuntimeException('A target UD partition operation marker is active: '.implode(', ', array_map('basename', array_slice($conflicts, 0, 6))));
    }
}

function adapter_certified_rc_process(string $cmdline, string $cwd = ''): ?array
{
    $tokens = array_values(array_filter(explode("\0", $cmdline), static fn(string $token): bool => $token !== ''));
    $certified = [
        '/usr/local/emhttp/plugins/unassigned.devices/scripts/rc.unassigned',
        '/usr/local/sbin/rc.unassigned',
    ];
    foreach ($tokens as $index => $token) {
        $candidate = $token;
        if (!str_starts_with($candidate, '/') && $cwd !== '') {
            $candidate = rtrim($cwd, '/').'/'.$candidate;
        }
        $matches = in_array($token, $certified, true) || in_array($candidate, $certified, true);
        if (!$matches) {
            $resolved = realpath($candidate);
            $official = realpath($certified[0]);
            $matches = $resolved !== false && $official !== false && $resolved === $official;
        }
        if ($matches) {
            return ['path' => $token, 'action' => (string)($tokens[$index + 1] ?? '')];
        }
    }
    return null;
}

function adapter_rc_mutators(string $procRoot = '/proc'): array
{
    $busy = [];
    $entries = @scandir($procRoot);
    if (!is_array($entries)) {
        throw new RuntimeException('The process table cannot be inspected for active UD operations.');
    }
    foreach ($entries as $entry) {
        if (preg_match('/\A[0-9]+\z/', $entry) !== 1) {
            continue;
        }
        try {
            $cmdline = adapter_read_bounded_file(rtrim($procRoot, '/').'/'.$entry.'/cmdline', 65536);
        } catch (Throwable) {
            continue;
        }
        $cwd = (string)@readlink(rtrim($procRoot, '/').'/'.$entry.'/cwd');
        $info = adapter_certified_rc_process($cmdline, $cwd);
        if ($info !== null) {
            $busy[] = 'pid='.$entry.' action='.($info['action'] !== '' ? $info['action'] : 'unknown');
        }
    }
    return $busy;
}

function adapter_target_preclear_processes(string $kernelName, string $procRoot = '/proc'): array
{
    $busy = [];
    $entries = @scandir($procRoot);
    if (!is_array($entries)) {
        throw new RuntimeException('The process table cannot be inspected for active Preclear operations.');
    }
    $targetPattern = '/(?:\A|[\s=,:])(?:\/dev\/)?'.preg_quote($kernelName, '/').'(?:[0-9]+)?(?:\z|[\s,])/i';
    foreach ($entries as $entry) {
        if (preg_match('/\A[0-9]+\z/', $entry) !== 1) {
            continue;
        }
        try {
            $cmdline = adapter_read_bounded_file(rtrim($procRoot, '/').'/'.$entry.'/cmdline', 65536);
        } catch (Throwable) {
            continue;
        }
        $text = str_replace("\0", ' ', $cmdline);
        if (stripos($text, 'preclear') !== false && preg_match($targetPattern, $text) === 1) {
            $busy[] = 'pid='.$entry.' target='.$kernelName;
        }
    }
    return $busy;
}

function adapter_assert_no_target_mutators(string $kernelName): void
{
    $busy = adapter_rc_mutators();
    if ($busy) {
        throw new RuntimeException('A compatible rc.unassigned process is still in flight: '.implode(', ', array_slice($busy, 0, 6)));
    }
    $preclear = adapter_target_preclear_processes($kernelName);
    if ($preclear) {
        throw new RuntimeException('A target Preclear process is still in flight: '.implode(', ', array_slice($preclear, 0, 6)));
    }
}

function adapter_assert_live_identity(array $state): array
{
    $current = adapter_device_identity((string)$state['kernel_name']);
    adapter_assert_identity_matches($state['identity'], $current);
    return $current;
}

function adapter_barrier_sample(array $state, string $mode, ?string $baseline = null): array
{
    adapter_assert_live_identity($state);
    adapter_assert_owned_root_marker($state);
    adapter_assert_target_markers_quiet($state);
    adapter_assert_no_target_mutators((string)$state['kernel_name']);
    $inspection = adapter_inspect_device((string)$state['kernel_name'], true);
    $topology = adapter_topology_snapshot($inspection);
    if (adapter_topology_without_mount_state($topology) !== adapter_topology_without_mount_state($state['topology'])) {
        throw new RuntimeException('UD disk, partition, filesystem, or mountpoint topology changed while the barrier was held.');
    }
    if ($mode === 'exact') {
        if ($topology !== $state['topology'] || $inspection['mount_snapshot'] !== $state['mount_snapshot']) {
            throw new RuntimeException('UD topology or target mountinfo changed while acquiring the barrier.');
        }
    } elseif ($mode === 'unmounted') {
        foreach ($topology['partitions'] as $partition) {
            if (($partition['mounted'] ?? false) === true) {
                throw new RuntimeException('A target UD partition remains mounted: '.(string)$partition['device']);
            }
        }
        if ($inspection['mount_snapshot'] !== []) {
            throw new RuntimeException('A target block device still has an active mount table entry.');
        }
    } elseif ($mode !== 'current') {
        throw new InvalidArgumentException('Unknown barrier validation mode.');
    }
    $signature = hash('sha256', serialize([$topology, $inspection['mount_snapshot']]));
    if ($baseline !== null && $signature !== $baseline) {
        throw new RuntimeException('UD topology or target mountinfo changed during the stable barrier window.');
    }
    return ['signature' => $signature, 'inspection' => $inspection];
}

function adapter_wait_for_barrier(array $state, string $mode): array
{
    $started = hrtime(true);
    $stableSince = null;
    $samples = 0;
    $baseline = null;
    $lastError = 'no stable sample was obtained';
    while (true) {
        try {
            $sample = adapter_barrier_sample($state, $mode, $baseline);
            if ($baseline === null) {
                $baseline = $sample['signature'];
                $stableSince = hrtime(true);
                $samples = 1;
            } else {
                $samples++;
            }
            if ($stableSince !== null
                && (hrtime(true) - $stableSince) >= ADAPTER_BARRIER_STABLE_US * 1000
                && $samples >= 3) {
                return $sample;
            }
        } catch (Throwable $error) {
            $lastError = $error->getMessage();
            $stableSince = null;
            $samples = 0;
            $baseline = null;
        }
        if ((hrtime(true) - $started) >= ADAPTER_BARRIER_TIMEOUT_US * 1000) {
            throw new RuntimeException('UD operation barrier did not become continuously stable: '.$lastError);
        }
        usleep(100000);
    }
}

function adapter_assert_release_guard(array $state, string $mode): void
{
    adapter_barrier_sample($state, $mode);
}

function adapter_acquire_root_marker(array &$state, string $statePath): void
{
    $marker = adapter_root_marker_path((string)$state['kernel_name']);
    $token = (string)$state['marker_token'];
    $state['acquiring_marker'] = $marker;
    $state['marker_create_started'] = true;
    $state['updated_at'] = gmdate('c');
    adapter_write_state($statePath, $state);
    adapter_effect_log($state, 'root_marker_acquire', 'before');
    if (file_exists($marker) || is_link($marker)) {
        adapter_effect_log($state, 'root_marker_acquire', 'after', ['result' => 'error', 'error' => 'marker already exists']);
        throw new RuntimeException('UD already has a root operation marker for '.basename($marker));
    }
    $handle = @fopen($marker, 'x+b');
    if (!is_resource($handle)) {
        adapter_effect_log($state, 'root_marker_acquire', 'after', ['result' => 'error', 'error' => 'exclusive create failed']);
        throw new RuntimeException('Unable to acquire the UD root operation marker.');
    }
    $written = @fwrite($handle, $token);
    $synced = @fflush($handle) && (!function_exists('fsync') || @fsync($handle));
    @fclose($handle);
    @chmod($marker, 0600);
    if ($written !== strlen($token) || !$synced) {
        @unlink($marker);
        adapter_effect_log($state, 'root_marker_acquire', 'after', ['result' => 'error', 'error' => 'marker synchronization failed']);
        throw new RuntimeException('Unable to synchronize the UD root operation marker.');
    }
    $state['marker_acquired'] = true;
    $state['marker_acquired_at'] = gmdate('c');
    $state['acquired_markers'] = [$marker];
    $state['acquiring_marker'] = '';
    $state['updated_at'] = gmdate('c');
    adapter_write_state($statePath, $state);
    adapter_effect_log($state, 'root_marker_acquire', 'after', ['result' => 'ok']);
}

function adapter_release_root_marker(array &$state, string $statePath, string $terminalPhase, string $mode): void
{
    adapter_assert_release_guard($state, $mode);
    $marker = adapter_root_marker_path((string)$state['kernel_name']);
    $state['marker_release_started'] = true;
    $state['updated_at'] = gmdate('c');
    adapter_write_state($statePath, $state);
    adapter_effect_log($state, 'root_marker_release', 'before');
    if (!@unlink($marker) && file_exists($marker)) {
        try {
            adapter_effect_log($state, 'root_marker_release', 'after', ['result' => 'error', 'error' => 'unlink failed']);
        } catch (Throwable $logError) {
            throw new RuntimeException('Unable to release the UD root operation marker; failure logging also failed: '.$logError->getMessage());
        }
        throw new RuntimeException('Unable to release the UD root operation marker.');
    }
    $state['marker_acquired'] = false;
    $state['marker_released_at'] = gmdate('c');
    $state['acquired_markers'] = [];
    $state['acquiring_marker'] = '';
    $state['phase'] = $terminalPhase;
    $state['updated_at'] = gmdate('c');
    adapter_write_state($statePath, $state);
    adapter_effect_log($state, 'root_marker_release', 'after', ['result' => 'ok']);
}

function adapter_delete_state(string $path): void
{
    if (!@unlink($path) && file_exists($path)) {
        throw new RuntimeException('Unable to remove completed UD adapter state.');
    }
}

function adapter_quiesce(string $kernelName, string $jobId, array $ud): void
{
    $path = adapter_state_path($jobId);
    if (is_file($path)) {
        $existing = adapter_read_state($path, $kernelName, $ud, $jobId);
        if (($existing['phase'] ?? '') === 'quiesced') {
            adapter_wait_for_barrier($existing, 'exact');
            adapter_json(['schema_version' => 1, 'ok' => true, 'supported' => true, 'version' => $ud['version'], 'message' => 'The narrow UD root operation barrier is already stable.']);
        }
        throw new RuntimeException('A non-terminal UD adapter state already exists for this job.');
    }
    $identity = adapter_device_identity($kernelName);
    $inspection = adapter_inspect_device($kernelName);
    adapter_assert_identity_matches($identity, adapter_device_identity($kernelName));
    $state = [
        'schema_version' => ADAPTER_SCHEMA_VERSION,
        'job_id' => $jobId,
        'kernel_name' => $kernelName,
        'edition' => $ud['edition'],
        'version' => $ud['version'],
        'device' => $inspection['device'],
        'phase' => 'prepared',
        'created_at' => gmdate('c'),
        'updated_at' => gmdate('c'),
        'identity' => $identity,
        'partitions' => $inspection['partitions'],
        'topology' => adapter_topology_snapshot($inspection),
        'mount_snapshot' => $inspection['mount_snapshot'],
        'marker_token' => adapter_marker_token($jobId),
        'operation_markers' => [adapter_root_marker_path($kernelName)],
        'acquired_markers' => [],
        'acquiring_marker' => '',
        'marker_acquired' => false,
        'marker_create_started' => false,
        'marker_release_started' => false,
    ];
    adapter_write_state($path, $state);
    try {
        $state['phase'] = 'acquiring_ud_markers';
        $state['updated_at'] = gmdate('c');
        adapter_write_state($path, $state);
        adapter_acquire_root_marker($state, $path);
        $state['phase'] = 'ud_markers_acquired';
        $state['updated_at'] = gmdate('c');
        adapter_write_state($path, $state);
        adapter_wait_for_barrier($state, 'exact');
        $state['phase'] = 'quiesced';
        $state['updated_at'] = gmdate('c');
        adapter_write_state($path, $state);
    } catch (Throwable $error) {
        $state['last_error'] = $error->getMessage();
        $state['updated_at'] = gmdate('c');
        try {
            adapter_write_state($path, $state);
        } catch (Throwable $stateError) {
            throw new RuntimeException($error->getMessage().'; preserving barrier state also failed: '.$stateError->getMessage(), 0, $error);
        }
        throw $error;
    }
    adapter_log('quiesce_complete', ['job_id' => $jobId, 'kernel_name' => $kernelName, 'mode' => 'root_marker_only']);
    adapter_json(['schema_version' => 1, 'ok' => true, 'supported' => true, 'version' => $ud['version'], 'message' => 'The narrow UD root operation barrier is stable; no UD share, script, or JSON state was changed.']);
}

function adapter_finalize(string $kernelName, string $jobId, array $ud): void
{
    $path = adapter_state_path($jobId);
    $state = adapter_read_state($path, $kernelName, $ud, $jobId);
    if (($state['phase'] ?? '') !== 'quiesced') {
        throw new RuntimeException('UD adapter state is not ready for finalize.');
    }
    adapter_wait_for_barrier($state, 'unmounted');
    $state['phase'] = 'finalizing';
    $state['finalize_barrier_verified_at'] = gmdate('c');
    $state['updated_at'] = gmdate('c');
    adapter_write_state($path, $state);
    adapter_release_root_marker($state, $path, 'finalized', 'unmounted');
    adapter_delete_state($path);
    adapter_log('finalize_complete', ['job_id' => $jobId, 'kernel_name' => $kernelName, 'mode' => 'root_marker_only']);
    adapter_json(['schema_version' => 1, 'ok' => true, 'supported' => true, 'version' => $ud['version'], 'message' => 'All target mounts are gone and the UD barrier was released; UD metadata remains owned by Unassigned Devices.']);
}

function adapter_rollback(string $kernelName, string $jobId, array $ud): void
{
    $path = adapter_state_path($jobId);
    $state = adapter_read_state($path, $kernelName, $ud, $jobId);
    $rollbackPhases = [
        'prepared', 'acquiring_ud_markers', 'ud_markers_acquired',
        'removing_shares', 'shares_removed', 'running_unmount_hook',
        'hooks_run', 'quiesced', 'rollback_failed', 'rolled_back',
    ];
    if (!in_array((string)$state['phase'], $rollbackPhases, true)) {
        throw new RuntimeException('UD adapter phase is beyond the reversible barrier boundary: '.(string)$state['phase']);
    }
    adapter_assert_live_identity($state);
    $marker = adapter_root_marker_path($kernelName);
    $record = adapter_marker_record($marker);
    if (($record['exists'] ?? false) === true) {
        adapter_validate_marker_record($record, (string)$state['marker_token'], time());
        adapter_wait_for_barrier($state, 'current');
        $state['phase'] = 'rollback_failed';
        $state['updated_at'] = gmdate('c');
        adapter_write_state($path, $state);
        adapter_release_root_marker($state, $path, 'rolled_back', 'current');
    } elseif (adapter_truthy($state['marker_acquired'] ?? false) && !adapter_truthy($state['marker_release_started'] ?? false)) {
        throw new RuntimeException('The owned UD root marker disappeared before rollback; state is preserved for diagnostics.');
    } else {
        $inspection = adapter_inspect_device($kernelName, false);
        if (adapter_topology_without_mount_state(adapter_topology_snapshot($inspection))
            !== adapter_topology_without_mount_state($state['topology'])) {
            throw new RuntimeException('UD topology changed before marker-free rollback cleanup.');
        }
        adapter_assert_no_target_mutators($kernelName);
        $state['phase'] = 'rolled_back';
        $state['updated_at'] = gmdate('c');
        adapter_write_state($path, $state);
    }
    adapter_delete_state($path);
    adapter_log('rollback_complete', ['job_id' => $jobId, 'kernel_name' => $kernelName, 'mode' => 'barrier_release_only']);
    adapter_json(['schema_version' => 1, 'ok' => true, 'supported' => true, 'version' => $ud['version'], 'message' => 'The UD root operation barrier was released; no share, script, or UD metadata rollback was required.']);
}

ob_start();
try {
    $action = (string)($argv[1] ?? '');
    $GLOBALS['adapter_action'] = $action;
    $kernelName = (string)($argv[2] ?? '');
    $jobId = (string)($argv[3] ?? '');
    if (!in_array($action, ['inspect', 'quiesce', 'finalize', 'rollback'], true)) {
        adapter_fail('Invalid UD adapter action.');
    }
    if (preg_match('/\Asd[a-z]+\z/', $kernelName) !== 1) {
        adapter_fail('Invalid kernel device name.');
    }
    if (preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/', $jobId) !== 1) {
        adapter_fail('Invalid job identifier.');
    }
    $ud = adapter_require_supported_ud();
    $_SERVER['DOCUMENT_ROOT'] = '/usr/local/emhttp';
    $_SERVER['REQUEST_URI'] = '/';
    try {
        // UD defines state at file scope and its helpers read that state through
        // $GLOBALS. Requiring the library inside a function breaks that contract.
        require_once ADAPTER_UD_LIB;
    } catch (Throwable $error) {
        adapter_fail('Unable to load the installed Unassigned Devices library: '.$error->getMessage(), $ud, false);
    }
    $capabilityError = adapter_ud_runtime_capability_error();
    if ($capabilityError !== '') {
        adapter_fail($capabilityError, $ud, false);
    }
    if ($action === 'inspect') {
        $identity = adapter_device_identity($kernelName);
        $inspection = adapter_inspect_device($kernelName);
        adapter_assert_identity_matches($identity, adapter_device_identity($kernelName));
        adapter_json([
            'schema_version' => 1,
            'ok' => true,
            'supported' => true,
            'version' => $ud['version'],
            'message' => 'Installed Unassigned Devices integration provides the required narrow read-only metadata and operation-barrier capabilities.',
            'details' => [
                'edition' => $ud['edition'],
                'device' => $inspection['device'],
                'identity' => $identity,
                'partitions' => array_map(static fn(array $partition): array => [
                    'device' => $partition['device'],
                    'mounted' => $partition['mounted'],
                    'mountpoint' => $partition['mountpoint'],
                    'fstype' => $partition['fstype'],
                    'shared' => $partition['shared'],
                ], $inspection['partitions']),
            ],
        ]);
    }
    if ($action === 'quiesce') {
        adapter_quiesce($kernelName, $jobId, $ud);
    } elseif ($action === 'finalize') {
        adapter_finalize($kernelName, $jobId, $ud);
    } else {
        adapter_rollback($kernelName, $jobId, $ud);
    }
} catch (Throwable $error) {
    $failureDetails = [
        'action' => (string)($argv[1] ?? ''),
        'kernel_name' => (string)($argv[2] ?? ''),
        'job_id' => (string)($argv[3] ?? ''),
        'version' => (string)($ud['version'] ?? ''),
        'edition' => (string)($ud['edition'] ?? ''),
        'exception_type' => get_class($error),
        'exception_file' => $error->getFile(),
        'exception_line' => $error->getLine(),
    ];
    $phase = adapter_failure_phase((string)($argv[3] ?? ''), (string)($argv[2] ?? ''));
    if ($phase !== '') {
        $failureDetails['phase'] = $phase;
    }
    adapter_fail($error->getMessage(), $failureDetails);
}
