<?php
declare(strict_types=1);

const GUARDIAN_PLUGIN_ROOT = '/usr/local/emhttp/plugins/unassigned.devices/usb-guardian';
const GUARDIAN_BINARY = GUARDIAN_PLUGIN_ROOT.'/bin/usb-guardian';
const GUARDIAN_CONFIG_ROOT = '/boot/config/plugins/unassigned.devices/usb-guardian';
const GUARDIAN_CONFIG_FILE = GUARDIAN_CONFIG_ROOT.'/usb.guardian.cfg';
const GUARDIAN_DEFAULT_CONFIG = GUARDIAN_PLUGIN_ROOT.'/default.cfg';
const GUARDIAN_LOG_DIR = GUARDIAN_CONFIG_ROOT.'/logs';
const GUARDIAN_RUN_ROOT = '/run/ud-usb-guardian';
const GUARDIAN_JOB_DIR = GUARDIAN_RUN_ROOT.'/jobs';
const GUARDIAN_DIAGNOSTIC_DIR = GUARDIAN_RUN_ROOT.'/diagnostics';
const GUARDIAN_AUTHORITY_FILE = GUARDIAN_RUN_ROOT.'/authority.json';
const GUARDIAN_LEASE_JOB_MAX_BYTES = 262144;

final class GuardianApiException extends RuntimeException
{
    public int $httpStatus;
    public array $details;

    public function __construct(string $message, int $httpStatus = 500, array $details = [])
    {
        parent::__construct($message);
        $this->httpStatus = $httpStatus;
        $this->details = $details;
    }
}

function guardian_json_response(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, max-age=0');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function guardian_request_string(string $name, int $minLength, int $maxLength, string $pattern): string
{
    $value = $_POST[$name] ?? null;
    if (!is_string($value) || strlen($value) < $minLength || strlen($value) > $maxLength || preg_match($pattern, $value) !== 1) {
        throw new GuardianApiException("Invalid parameter: {$name}", 400);
    }
    return $value;
}

function guardian_boot_id(): string
{
    $value = trim((string)@file_get_contents('/proc/sys/kernel/random/boot_id'));
    return preg_match('/\A[0-9a-f-]{36}\z/', $value) === 1 ? $value : '';
}

function guardian_mountinfo_unescape(string $value): string
{
    return strtr($value, ['\\040' => ' ', '\\011' => "\t", '\\012' => "\n", '\\134' => '\\']);
}

function guardian_mount_paths_overlap(string $left, string $right): bool
{
    $left = rtrim($left, '/');
    $right = rtrim($right, '/');
    return $left === $right || str_starts_with($left, $right.'/') || str_starts_with($right, $left.'/');
}

function guardian_boot_mount_status_from_mountinfo(string $mountInfo, string $persistentRoot = GUARDIAN_CONFIG_ROOT): array
{
    $matches = [];
    foreach (preg_split('/\r?\n/', $mountInfo) ?: [] as $line) {
        if (trim($line) === '') {
            continue;
        }
        $fields = preg_split('/\s+/', trim($line));
        if (!is_array($fields) || count($fields) < 10) {
            return ['ok' => false, 'reason' => 'mountinfo is malformed'];
        }
        $separator = array_search('-', $fields, true);
        if (!is_int($separator) || $separator < 6 || $separator + 3 >= count($fields)) {
            return ['ok' => false, 'reason' => 'mountinfo has no valid separator'];
        }
        $mountPoint = guardian_mountinfo_unescape((string)$fields[4]);
        if ($mountPoint !== '/boot'
            && str_starts_with($mountPoint, '/boot/')
            && guardian_mount_paths_overlap($mountPoint, $persistentRoot)) {
            return ['ok' => false, 'reason' => 'a nested mount shadows the persistent plugin directory', 'mountpoint' => $mountPoint];
        }
        if ($mountPoint !== '/boot') {
            continue;
        }
        $matches[] = [
            'root' => guardian_mountinfo_unescape((string)$fields[3]),
            'options' => explode(',', (string)$fields[5]),
            'fstype' => strtolower((string)$fields[$separator + 1]),
            'source' => guardian_mountinfo_unescape((string)$fields[$separator + 2]),
        ];
    }
    if (count($matches) !== 1) {
        return ['ok' => false, 'reason' => count($matches) === 0 ? '/boot is not a separate mount' : '/boot has ambiguous stacked mounts'];
    }
    $mount = $matches[0];
    if ($mount['root'] !== '/') {
        return ['ok' => false, 'reason' => '/boot is a bind or subdirectory mount'];
    }
    if (!in_array($mount['fstype'], ['vfat', 'msdos', 'fat'], true)) {
        return ['ok' => false, 'reason' => '/boot is not a FAT filesystem', 'fstype' => $mount['fstype']];
    }
    if (!str_starts_with($mount['source'], '/dev/')) {
        return ['ok' => false, 'reason' => '/boot does not have a block-device source', 'source' => $mount['source']];
    }
    if (!in_array('rw', $mount['options'], true)) {
        return ['ok' => false, 'reason' => '/boot is not writable'];
    }
    return ['ok' => true, 'reason' => '', 'fstype' => $mount['fstype'], 'source' => $mount['source']];
}

function guardian_boot_mount_status(): array
{
    $mountInfo = @file_get_contents('/proc/self/mountinfo', false, null, 0, 2097152);
    if (!is_string($mountInfo) || $mountInfo === '' || strlen($mountInfo) >= 2097152) {
        return ['ok' => false, 'reason' => 'cannot read a bounded /proc/self/mountinfo snapshot'];
    }
    return guardian_boot_mount_status_from_mountinfo($mountInfo);
}

function guardian_assert_persistent_boot_mount(): void
{
    $status = guardian_boot_mount_status();
    if (($status['ok'] ?? false) !== true) {
        throw new GuardianApiException(
            'The Unraid boot flash is not mounted safely, so persistent logging cannot be guaranteed. Keep the USB device connected and restore the /boot flash mount before retrying.',
            503,
            ['reason' => ['code' => 'persistent_boot_mount_unavailable', 'detail' => (string)($status['reason'] ?? 'unknown')]]
        );
    }
}

function guardian_unraid_version(): string
{
    $data = @parse_ini_file('/etc/unraid-version');
    return is_array($data) ? (string)($data['version'] ?? '') : '';
}

function guardian_require_runtime(): void
{
    if (PHP_OS_FAMILY !== 'Linux' || !is_readable('/proc/self/mountinfo') || !is_dir('/sys/class/block')) {
        throw new GuardianApiException('Required Linux device interfaces are unavailable.', 503);
    }
    if (is_dir('/usr/local/emhttp/plugins/usb.guardian')) {
        throw new GuardianApiException('Remove the standalone USB Guardian plugin before using built-in safe eject.', 409);
    }
}

function guardian_require_not_maintaining(): void
{
    if (file_exists(GUARDIAN_RUN_ROOT.'/maintenance')) {
        throw new GuardianApiException('Unassigned Devices is being updated or removed. Try again after it is ready.', 409);
    }
}

function guardian_ensure_runtime_dirs(): void
{
    guardian_assert_persistent_boot_mount();
    foreach ([GUARDIAN_CONFIG_ROOT, GUARDIAN_LOG_DIR, GUARDIAN_RUN_ROOT, GUARDIAN_JOB_DIR, GUARDIAN_DIAGNOSTIC_DIR] as $path) {
        if (!is_dir($path) && !@mkdir($path, 0700, true) && !is_dir($path)) {
            throw new GuardianApiException("Cannot create runtime directory: {$path}");
        }
        @chmod($path, 0700);
    }
    if (!is_file(GUARDIAN_CONFIG_FILE) && is_file(GUARDIAN_DEFAULT_CONFIG)) {
        if (!@copy(GUARDIAN_DEFAULT_CONFIG, GUARDIAN_CONFIG_FILE)) {
            throw new GuardianApiException('Cannot initialize USB Guardian settings.');
        }
        @chmod(GUARDIAN_CONFIG_FILE, 0600);
    }
}

function guardian_rotate_flat_log(string $path): void
{
    if (dirname($path) !== GUARDIAN_LOG_DIR || !in_array(basename($path), ['api.log', 'launcher.log'], true)) {
        throw new GuardianApiException('Invalid flat log path.');
    }
    if (!is_file($path) || (int)@filesize($path) < 1048576) {
        return;
    }
    @unlink($path.'.2');
    if (is_file($path.'.1')) {
        @rename($path.'.1', $path.'.2');
    }
    @rename($path, $path.'.1');
}

function guardian_api_log(string $event, array $context = []): void
{
    if ((guardian_boot_mount_status()['ok'] ?? false) !== true) {
        return;
    }
    if (!is_dir(GUARDIAN_LOG_DIR)) {
        @mkdir(GUARDIAN_LOG_DIR, 0700, true);
    }
    if (in_array($event, ['api_error', 'core_command_failed'], true)) {
        $signature = hash('sha256', $event.'|'.json_encode($context, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
        $rateFile = GUARDIAN_RUN_ROOT.'/api-log-'.$signature;
        if (is_file($rateFile) && (time() - (int)@filemtime($rateFile)) < 60) {
            return;
        }
        if (is_dir(GUARDIAN_RUN_ROOT)) {
            @touch($rateFile);
            @chmod($rateFile, 0600);
        }
    }
    if (!is_dir(GUARDIAN_RUN_ROOT)) {
        @mkdir(GUARDIAN_RUN_ROOT, 0700, true);
    }
    $rotationHandle = @fopen(GUARDIAN_RUN_ROOT.'/flat-log.lock', 'c+');
    if (is_resource($rotationHandle)) {
        @flock($rotationHandle, LOCK_EX);
    }
    guardian_rotate_flat_log(GUARDIAN_LOG_DIR.'/api.log');
    $record = [
        'timestamp' => gmdate('c'),
        'event' => $event,
        'request_id' => $GLOBALS['guardian_request_id'] ?? '',
        'client' => (string)($_SERVER['REMOTE_ADDR'] ?? ''),
    ];
    foreach ($context as $key => $value) {
        if (is_scalar($value) || $value === null || is_array($value)) {
            $record[$key] = $value;
        }
    }
    $line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)."\n";
    $handle = @fopen(GUARDIAN_LOG_DIR.'/api.log', 'ab');
    if ($handle !== false) {
        if (@flock($handle, LOCK_EX)) {
            @fwrite($handle, $line);
            @fflush($handle);
            if (function_exists('fsync')) {
                @fsync($handle);
            }
            @flock($handle, LOCK_UN);
        }
        @fclose($handle);
        @chmod(GUARDIAN_LOG_DIR.'/api.log', 0600);
    }
    if (is_resource($rotationHandle)) {
        @flock($rotationHandle, LOCK_UN);
        @fclose($rotationHandle);
    }
}

function guardian_run_process(array $command, int $timeoutSeconds, int $maxOutputBytes = 2097152): array
{
    $descriptors = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $pipes = [];
    $process = @proc_open($command, $descriptors, $pipes, null, null, ['bypass_shell' => true]);
    if (!is_resource($process)) {
        throw new GuardianApiException('Unable to start USB Guardian core.');
    }
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $stdout = '';
    $stderr = '';
    $deadline = microtime(true) + $timeoutSeconds;
    $lastStatus = null;
    $timedOut = false;
    $tooLarge = false;

    while (true) {
        $stdout .= (string)stream_get_contents($pipes[1]);
        $stderr .= (string)stream_get_contents($pipes[2]);
        if (strlen($stdout) + strlen($stderr) > $maxOutputBytes) {
            $tooLarge = true;
            @proc_terminate($process, 15);
            break;
        }
        $lastStatus = proc_get_status($process);
        if (!$lastStatus['running']) {
            break;
        }
        if (microtime(true) >= $deadline) {
            $timedOut = true;
            @proc_terminate($process, 15);
            usleep(250000);
            $afterTerm = proc_get_status($process);
            if ($afterTerm['running']) {
                @proc_terminate($process, 9);
            }
            break;
        }
        usleep(50000);
    }

    $stdout .= (string)stream_get_contents($pipes[1]);
    $stderr .= (string)stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $closeCode = proc_close($process);
    $exitCode = $closeCode >= 0 ? $closeCode : (int)($lastStatus['exitcode'] ?? -1);
    if ($timedOut) {
        throw new GuardianApiException('USB Guardian core timed out.', 504);
    }
    if ($tooLarge) {
        throw new GuardianApiException('USB Guardian core returned too much output.');
    }
    return ['exit_code' => $exitCode, 'stdout' => $stdout, 'stderr' => $stderr];
}

function guardian_core_json(array $arguments, int $timeoutSeconds = 15): array
{
    if (!is_file(GUARDIAN_BINARY) || !is_executable(GUARDIAN_BINARY)) {
        throw new GuardianApiException('USB Guardian core binary is unavailable.', 503);
    }
    $result = guardian_run_process(array_merge([GUARDIAN_BINARY], $arguments), $timeoutSeconds);
    $decoded = json_decode(trim($result['stdout']), true);
    if ($result['exit_code'] !== 0 || !is_array($decoded)) {
        $stderrJson = json_decode(trim($result['stderr']), true);
        $message = is_array($decoded) && is_string($decoded['error'] ?? null)
            ? $decoded['error']
            : (is_array($stderrJson) && is_string($stderrJson['error'] ?? null) ? $stderrJson['error'] : 'USB Guardian core command failed.');
        guardian_api_log('core_command_failed', [
            'command' => (string)($arguments[0] ?? ''),
            'exit_code' => $result['exit_code'],
            'stderr' => substr(trim($result['stderr']), 0, 2000),
        ]);
        throw new GuardianApiException($message, 503, ['core_exit_code' => $result['exit_code']]);
    }
    return $decoded;
}

function guardian_list_devices(): array
{
    $payload = guardian_core_json(['list', '--json', '--config', GUARDIAN_CONFIG_FILE], 20);
    if (!isset($payload['devices']) || !is_array($payload['devices'])) {
        throw new GuardianApiException('USB Guardian core returned an invalid device list.', 503);
    }
    $payload['meta'] = is_array($payload['meta'] ?? null) ? $payload['meta'] : [];
    $payload['meta']['boot_id'] = guardian_boot_id();
    $payload['meta']['unraid_version'] = guardian_unraid_version();
    return $payload;
}

function guardian_device_token(array $device): string
{
    return is_string($device['target'] ?? null) ? $device['target'] : '';
}

function guardian_find_device_by_token(array $listPayload, string $token): ?array
{
    foreach ($listPayload['devices'] as $device) {
        if (is_array($device)) {
            $candidate = guardian_device_token($device);
            if ($candidate !== '' && hash_equals($candidate, $token)) {
                return $device;
            }
        }
    }
    return null;
}

function guardian_default_settings(): array
{
    return [
        'ENABLED' => 'yes',
        'LOG_LEVEL' => 'info',
        'PERSISTENT_LOGGING' => 'yes',
        'LOG_RETENTION_DAYS' => '30',
        'MAX_LOG_MIB' => '128',
        'LOG_KEEP' => '20',
        'SETTLE_SECONDS' => '30',
        'SHFS_HEALTH_SECONDS' => '5',
        'ENABLE_SG_IO' => 'yes',
    ];
}

function guardian_load_settings(): array
{
    $settings = guardian_default_settings();
    $source = is_file(GUARDIAN_CONFIG_FILE) ? GUARDIAN_CONFIG_FILE : GUARDIAN_DEFAULT_CONFIG;
    $parsed = @parse_ini_file($source, false, INI_SCANNER_RAW);
    if (is_array($parsed)) {
        foreach ($settings as $key => $_value) {
            if (is_scalar($parsed[$key] ?? null)) {
                $settings[$key] = (string)$parsed[$key];
            }
        }
    }
    $settings['PERSISTENT_LOGGING'] = 'yes';
    return $settings;
}

function guardian_integer_setting(string $name, int $minimum, int $maximum): string
{
    $raw = guardian_request_string($name, 1, 8, '/\A[0-9]+\z/');
    $value = filter_var($raw, FILTER_VALIDATE_INT, ['options' => ['min_range' => $minimum, 'max_range' => $maximum]]);
    if ($value === false) {
        throw new GuardianApiException("Invalid setting: {$name}", 400);
    }
    return (string)$value;
}

function guardian_validate_settings_request(): array
{
    return [
        'ENABLED' => guardian_request_string('ENABLED', 2, 3, '/\A(?:yes|no)\z/'),
        'LOG_LEVEL' => guardian_request_string('LOG_LEVEL', 4, 5, '/\A(?:info|debug)\z/'),
        'PERSISTENT_LOGGING' => 'yes',
        'LOG_RETENTION_DAYS' => guardian_integer_setting('LOG_RETENTION_DAYS', 7, 365),
        'MAX_LOG_MIB' => guardian_integer_setting('MAX_LOG_MIB', 32, 2048),
        'LOG_KEEP' => guardian_integer_setting('LOG_KEEP', 5, 100),
        'SETTLE_SECONDS' => guardian_integer_setting('SETTLE_SECONDS', 2, 60),
        'SHFS_HEALTH_SECONDS' => guardian_integer_setting('SHFS_HEALTH_SECONDS', 2, 60),
        'ENABLE_SG_IO' => guardian_request_string('ENABLE_SG_IO', 2, 3, '/\A(?:yes|no)\z/'),
    ];
}

function guardian_is_enabled(): bool
{
    return guardian_load_settings()['ENABLED'] === 'yes';
}

function guardian_require_enabled(): void
{
    if (!guardian_is_enabled()) {
        throw new GuardianApiException('USB Guardian is disabled in Settings.', 409, ['code' => 'plugin_disabled']);
    }
}

function guardian_save_settings_guarded(array $settings): void
{
    $lockHandle = @fopen(GUARDIAN_RUN_ROOT.'/api.lock', 'c+');
    if ($lockHandle === false || !@flock($lockHandle, LOCK_EX | LOCK_NB)) {
        if (is_resource($lockHandle)) {
            fclose($lockHandle);
        }
        throw new GuardianApiException('USB Guardian settings cannot be changed while another operation is starting.', 409);
    }
    try {
        if (($settings['ENABLED'] ?? 'yes') !== 'yes' && guardian_has_active_job() !== null) {
            throw new GuardianApiException('USB Guardian cannot be disabled while a safe-eject operation is active.', 409);
        }
        guardian_save_settings($settings);
    } finally {
        @flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

function guardian_save_settings(array $settings): void
{
    guardian_ensure_runtime_dirs();
    $lines = [];
    foreach (guardian_default_settings() as $key => $_value) {
        $value = str_replace(['\\', '"', "\r", "\n"], ['\\\\', '\\"', '', ''], (string)$settings[$key]);
        $lines[] = $key.'="'.$value.'"';
    }
    $content = implode("\n", $lines)."\n";
    $temporary = GUARDIAN_CONFIG_FILE.'.tmp.'.bin2hex(random_bytes(8));
    if (@file_put_contents($temporary, $content, LOCK_EX) !== strlen($content)) {
        @unlink($temporary);
        throw new GuardianApiException('Unable to write USB Guardian settings.');
    }
    @chmod($temporary, 0600);
    if (!@rename($temporary, GUARDIAN_CONFIG_FILE)) {
        @unlink($temporary);
        throw new GuardianApiException('Unable to activate USB Guardian settings.');
    }
}

function guardian_delete_log_path(string $path, string $root): int
{
    $root = rtrim($root, DIRECTORY_SEPARATOR);
    if ($root === '' || !str_starts_with($path, $root.DIRECTORY_SEPARATOR)) {
        throw new GuardianApiException('Refusing to clear a path outside the USB Guardian log directory.');
    }
    if (is_link($path)) {
        if (!@unlink($path)) {
            throw new GuardianApiException('Unable to remove a symbolic link from the USB Guardian log directory.');
        }
        return 1;
    }
    if (is_dir($path)) {
        $entries = @scandir($path);
        if (!is_array($entries)) {
            throw new GuardianApiException('Unable to read a USB Guardian log subdirectory.');
        }
        $removed = 0;
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $removed += guardian_delete_log_path($path.DIRECTORY_SEPARATOR.$entry, $root);
        }
        if (!@rmdir($path)) {
            throw new GuardianApiException('Unable to remove an empty USB Guardian log subdirectory.');
        }
        return $removed + 1;
    }
    if (is_file($path)) {
        if (!@unlink($path)) {
            throw new GuardianApiException('Unable to remove a USB Guardian log file.');
        }
        return 1;
    }
    if (@lstat($path) !== false) {
        throw new GuardianApiException('The USB Guardian log directory contains an unsupported filesystem entry.');
    }
    return 0;
}

function guardian_clear_log_directory(string $root, string $preservedName = '.transaction.lock'): int
{
    if (is_link($root) || !is_dir($root)) {
        throw new GuardianApiException('The USB Guardian log directory is unavailable or unsafe.');
    }
    $entries = @scandir($root);
    if (!is_array($entries)) {
        throw new GuardianApiException('Unable to read the USB Guardian log directory.');
    }
    $removed = 0;
    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..' || $entry === $preservedName) {
            continue;
        }
        $removed += guardian_delete_log_path($root.DIRECTORY_SEPARATOR.$entry, $root);
    }
    return $removed;
}

function guardian_clear_logs(): array
{
    guardian_ensure_runtime_dirs();
    $apiLock = @fopen(GUARDIAN_RUN_ROOT.'/api.lock', 'c+');
    if (!is_resource($apiLock) || !@flock($apiLock, LOCK_EX | LOCK_NB)) {
        if (is_resource($apiLock)) {
            fclose($apiLock);
        }
        throw new GuardianApiException('Logs cannot be cleared while another USB Guardian operation is starting.', 409);
    }
    $transactionLock = null;
    $flatLogLock = null;
    $diagnosticsLock = null;
    try {
        if (guardian_has_active_job() !== null) {
            throw new GuardianApiException('Logs cannot be cleared while a safe-eject operation is active.', 409);
        }
        $activeMarkers = glob(GUARDIAN_LOG_DIR.'/transactions/*/active.json') ?: [];
        $adapterArtifacts = glob(GUARDIAN_RUN_ROOT.'/ud-adapter/*') ?: [];
        if ($activeMarkers || $adapterArtifacts) {
            throw new GuardianApiException('Logs cannot be cleared while transaction recovery evidence is active. Reboot or finish recovery first.', 409);
        }
        $diagnosticsLock = @fopen(GUARDIAN_RUN_ROOT.'/diagnostics.lock', 'c+');
        if (!is_resource($diagnosticsLock) || !@flock($diagnosticsLock, LOCK_EX | LOCK_NB)) {
            throw new GuardianApiException('Logs cannot be cleared while a diagnostics archive is being created.', 409);
        }
        $transactionLock = @fopen(GUARDIAN_LOG_DIR.'/.transaction.lock', 'c+');
        if (!is_resource($transactionLock) || !@flock($transactionLock, LOCK_EX | LOCK_NB)) {
            throw new GuardianApiException('Logs cannot be cleared because the transaction log is in use.', 409);
        }
        $flatLogLock = @fopen(GUARDIAN_RUN_ROOT.'/flat-log.lock', 'c+');
        if (!is_resource($flatLogLock) || !@flock($flatLogLock, LOCK_EX | LOCK_NB)) {
            throw new GuardianApiException('Logs cannot be cleared because a diagnostic log is being written.', 409);
        }
        $removed = guardian_clear_log_directory(GUARDIAN_LOG_DIR);
        return ['removed_entries' => $removed];
    } finally {
        if (is_resource($flatLogLock)) {
            @flock($flatLogLock, LOCK_UN);
            fclose($flatLogLock);
        }
        if (is_resource($transactionLock)) {
            @flock($transactionLock, LOCK_UN);
            fclose($transactionLock);
        }
        if (is_resource($diagnosticsLock)) {
            @flock($diagnosticsLock, LOCK_UN);
            fclose($diagnosticsLock);
        }
        @flock($apiLock, LOCK_UN);
        fclose($apiLock);
    }
}

function guardian_uuid_v4(): string
{
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    $hex = bin2hex($bytes);
    return substr($hex, 0, 8).'-'.substr($hex, 8, 4).'-'.substr($hex, 12, 4).'-'.substr($hex, 16, 4).'-'.substr($hex, 20);
}

function guardian_safe_job_file(string $jobId): string
{
    if (preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $jobId) !== 1) {
        throw new GuardianApiException('Invalid job identifier.', 400);
    }
    return GUARDIAN_JOB_DIR.'/'.$jobId.'.json';
}

function guardian_read_authority(): ?array
{
    if (!file_exists(GUARDIAN_AUTHORITY_FILE) && !is_link(GUARDIAN_AUTHORITY_FILE)) {
        return null;
    }
    if (!is_file(GUARDIAN_AUTHORITY_FILE) || is_link(GUARDIAN_AUTHORITY_FILE)) {
        throw new GuardianApiException('USB Guardian authority state is invalid. Reboot before retrying.', 409);
    }
    $size = @filesize(GUARDIAN_AUTHORITY_FILE);
    if (!is_int($size) || $size < 2 || $size > 4096) {
        throw new GuardianApiException('USB Guardian authority state has an invalid size. Reboot before retrying.', 409);
    }
    $contents = @file_get_contents(GUARDIAN_AUTHORITY_FILE);
    $authority = is_string($contents) ? json_decode($contents, true) : null;
    $bootId = guardian_boot_id();
    $keys = is_array($authority) ? array_keys($authority) : [];
    sort($keys);
    if (!is_array($authority)
        || $keys !== ['boot_id', 'generation', 'job_id', 'schema_version']
        || ($authority['schema_version'] ?? null) !== 1
        || !is_string($authority['boot_id'] ?? null)
        || $bootId === ''
        || !hash_equals($bootId, $authority['boot_id'])
        || !is_string($authority['job_id'] ?? null)
        || preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $authority['job_id']) !== 1
        || !is_int($authority['generation'] ?? null)
        || $authority['generation'] < 1) {
        throw new GuardianApiException('USB Guardian authority state is corrupt or belongs to another boot. Reboot before retrying.', 409);
    }
    return [
        'schema_version' => 1,
        'boot_id' => $authority['boot_id'],
        'job_id' => $authority['job_id'],
        'generation' => $authority['generation'],
    ];
}

function guardian_write_authority(array $authority): void
{
    $encoded = json_encode($authority, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)."\n";
    if (!is_string($encoded)) {
        throw new GuardianApiException('Unable to encode USB Guardian authority state.');
    }
    $temporary = GUARDIAN_RUN_ROOT.'/.authority.'.bin2hex(random_bytes(8)).'.tmp';
    if (@file_put_contents($temporary, $encoded, LOCK_EX) !== strlen($encoded)) {
        @unlink($temporary);
        throw new GuardianApiException('Unable to write USB Guardian authority state.');
    }
    if (!@chmod($temporary, 0600)) {
        @unlink($temporary);
        throw new GuardianApiException('Unable to protect USB Guardian authority state.');
    }
    $handle = @fopen($temporary, 'r+b');
    if ($handle === false || !function_exists('fsync') || !@fflush($handle) || !@fsync($handle)) {
        if (is_resource($handle)) {
            fclose($handle);
        }
        @unlink($temporary);
        throw new GuardianApiException('Unable to synchronize USB Guardian authority state.');
    }
    fclose($handle);
    if (!@rename($temporary, GUARDIAN_AUTHORITY_FILE)) {
        @unlink($temporary);
        throw new GuardianApiException('Unable to activate USB Guardian authority state.');
    }
    @chmod(GUARDIAN_AUTHORITY_FILE, 0600);
}

function guardian_next_authority(?array $previous, string $jobId): array
{
    $generation = $previous === null ? 1 : $previous['generation'] + 1;
    $bootId = guardian_boot_id();
    if (!is_int($generation) || $generation < 1) {
        throw new GuardianApiException('USB Guardian authority generation is exhausted. Reboot before retrying.', 409);
    }
    if ($bootId === '') {
        throw new GuardianApiException('Unable to establish the current boot identity.', 503);
    }
    return [
        'schema_version' => 1,
        'boot_id' => $bootId,
        'job_id' => $jobId,
        'generation' => $generation,
    ];
}

function guardian_attach_authority(array $payload, ?array $authority, string $jobId = ''): array
{
    $isLatest = $authority !== null && $jobId !== '' && hash_equals($authority['job_id'], $jobId);
    $payload['authority'] = $authority;
    $payload['generation'] = $authority['generation'] ?? 0;
    $payload['is_latest_job'] = $isLatest;
    return $payload;
}

function guardian_atomic_json_file(string $path, array $payload): void
{
    if (dirname($path) !== GUARDIAN_JOB_DIR) {
        throw new GuardianApiException('Invalid job state path.');
    }
    $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)."\n";
    $temporary = $path.'.tmp.'.bin2hex(random_bytes(6));
    if (@file_put_contents($temporary, $encoded, LOCK_EX) !== strlen($encoded)) {
        @unlink($temporary);
        throw new GuardianApiException('Unable to create job state.');
    }
    @chmod($temporary, 0600);
    if (!@rename($temporary, $path)) {
        @unlink($temporary);
        throw new GuardianApiException('Unable to activate job state.');
    }
}

function guardian_read_job_file(string $jobId): ?array
{
    $path = guardian_safe_job_file($jobId);
    if (!is_file($path) || is_link($path)) {
        return null;
    }
    $decoded = json_decode((string)@file_get_contents($path), true);
    return is_array($decoded) ? $decoded : null;
}

function guardian_read_lease_job_file(string $jobId, string $jobDir = GUARDIAN_JOB_DIR): array
{
    guardian_safe_job_file($jobId);
    $path = rtrim($jobDir, '/\\').DIRECTORY_SEPARATOR.$jobId.'.json';
    clearstatcache(true, $path);
    $before = @lstat($path);
    if (!is_array($before) || is_link($path) || (($before['mode'] & 0170000) !== 0100000)) {
        throw new GuardianApiException('The authoritative safe-eject job file is missing or is not a regular file.', 409);
    }
    $size = $before['size'] ?? null;
    if (!is_int($size) || $size < 2 || $size > GUARDIAN_LEASE_JOB_MAX_BYTES) {
        throw new GuardianApiException('The authoritative safe-eject job file has an invalid size.', 409);
    }
    $handle = @fopen($path, 'rb');
    if ($handle === false) {
        throw new GuardianApiException('The authoritative safe-eject job file cannot be read.', 409);
    }
    try {
        $opened = @fstat($handle);
        if (!is_array($opened)
            || (($opened['mode'] & 0170000) !== 0100000)
            || ($opened['dev'] ?? null) !== ($before['dev'] ?? null)
            || ($opened['ino'] ?? null) !== ($before['ino'] ?? null)
            || ($opened['size'] ?? null) !== $size) {
            throw new GuardianApiException('The authoritative safe-eject job file changed while it was being opened.', 409);
        }
        $contents = stream_get_contents($handle, $size + 1);
        if (!is_string($contents) || strlen($contents) !== $size || !feof($handle)) {
            throw new GuardianApiException('The authoritative safe-eject job file changed while it was being read.', 409);
        }
    } finally {
        fclose($handle);
    }
    try {
        $decoded = json_decode($contents, true, 64, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        throw new GuardianApiException('The authoritative safe-eject job file contains invalid JSON.', 409);
    }
    if (!is_array($decoded)) {
        throw new GuardianApiException('The authoritative safe-eject job file does not contain an object.', 409);
    }
    return $decoded;
}

function guardian_lease_usb_path(string $value): string
{
    if (strlen($value) < 12
        || strlen($value) > 1024
        || preg_match('/\Adevices(?:\/[A-Za-z0-9._:+-]+)+\z/D', $value) !== 1
        || preg_match('/\A[0-9]+-[0-9]+(?:\.[0-9]+)*\z/D', basename($value)) !== 1) {
        throw new GuardianApiException('The completed job contains an invalid USB sysfs path.', 409);
    }
    return $value;
}

function guardian_lease_usb_serial(mixed $value): string
{
    if (!is_string($value)) {
        throw new GuardianApiException('The completed job contains an invalid USB serial field.', 409);
    }
    if ($value !== ''
        && (strlen($value) > 255
            || trim($value) !== $value
            || preg_match('/\A[^\x00-\x1f\x7f]+\z/uD', $value) !== 1)) {
        throw new GuardianApiException('The completed job contains an invalid USB serial field.', 409);
    }
    return $value;
}

function guardian_lease_identity_from_job(string $jobId, array $job): array
{
    if (($job['schema_version'] ?? null) !== 1
        || !is_string($job['job_id'] ?? null)
        || !hash_equals($jobId, $job['job_id'])
        || ($job['state'] ?? null) !== 'completed'
        || ($job['terminal'] ?? null) !== true
        || ($job['safe_to_unplug'] ?? null) !== true
        || !is_array($job['device'] ?? null)) {
        throw new GuardianApiException('The authoritative job is not a completed safe-eject result.', 409);
    }
    $device = $job['device'];
    $path = is_string($device['usb_path'] ?? null) ? guardian_lease_usb_path($device['usb_path']) : '';
    $vid = $device['usb_vid'] ?? null;
    $pid = $device['usb_pid'] ?? null;
    if ($path === ''
        || !is_string($vid)
        || preg_match('/\A[0-9a-f]{4}\z/D', $vid) !== 1
        || !is_string($pid)
        || preg_match('/\A[0-9a-f]{4}\z/D', $pid) !== 1) {
        throw new GuardianApiException('The completed job contains invalid USB VID/PID identity.', 409);
    }
    $serial = guardian_lease_usb_serial($device['usb_serial'] ?? '');
    return [
        'usb_path' => $path,
        'usb_vid' => $vid,
        'usb_pid' => $pid,
        'usb_serial' => $serial,
    ];
}

function guardian_read_lease_sysfs_attribute(string $path, string $name, bool $required): string
{
    clearstatcache(true, $path);
    if (!file_exists($path) && !is_link($path)) {
        if ($required) {
            throw new GuardianApiException("USB sysfs {$name} is unavailable; device absence cannot be verified.", 409);
        }
        return '';
    }
    if (!is_file($path) || !is_readable($path)) {
        throw new GuardianApiException("USB sysfs {$name} is unreadable; device absence cannot be verified.", 409);
    }
    $contents = @file_get_contents($path, false, null, 0, 512);
    if (!is_string($contents) || strlen($contents) >= 512) {
        throw new GuardianApiException("USB sysfs {$name} cannot be read safely; device absence cannot be verified.", 409);
    }
    return trim($contents);
}

function guardian_assert_lease_usb_absent(array $identity, string $sysRoot = '/sys'): void
{
    $usbPath = guardian_lease_usb_path(is_string($identity['usb_path'] ?? null) ? $identity['usb_path'] : '');
    $vid = $identity['usb_vid'] ?? null;
    $pid = $identity['usb_pid'] ?? null;
    if (!is_string($vid)
        || preg_match('/\A[0-9a-f]{4}\z/D', $vid) !== 1
        || !is_string($pid)
        || preg_match('/\A[0-9a-f]{4}\z/D', $pid) !== 1) {
        throw new GuardianApiException('The lease USB VID/PID identity is invalid.', 409);
    }
    $serial = guardian_lease_usb_serial($identity['usb_serial'] ?? '');
    $root = rtrim($sysRoot, '/\\');
    if ($root === '' || str_contains($root, "\0") || !is_dir($root) || !is_readable($root)) {
        throw new GuardianApiException('USB sysfs is unavailable; device absence cannot be verified.', 503);
    }
    $ueventPath = $root.DIRECTORY_SEPARATOR.'kernel'.DIRECTORY_SEPARATOR.'uevent_seqnum';
    $ueventBefore = guardian_read_lease_sysfs_attribute($ueventPath, 'uevent_seqnum', true);
    if (preg_match('/\A[0-9]{1,20}\z/D', $ueventBefore) !== 1) {
        throw new GuardianApiException('The kernel uevent sequence is invalid; device absence cannot be verified.', 503);
    }
    $originalPath = $root.DIRECTORY_SEPARATOR.str_replace('/', DIRECTORY_SEPARATOR, $usbPath);
    clearstatcache(true, $originalPath);
    if (@lstat($originalPath) !== false || file_exists($originalPath) || is_link($originalPath)) {
        throw new GuardianApiException('The original USB sysfs path is present again. Do not unplug based on the previous approval.', 409, [
            'reason' => ['code' => 'usb_original_path_present', 'usb_path' => $usbPath],
        ]);
    }
    $scanRoot = $root.DIRECTORY_SEPARATOR.'bus'.DIRECTORY_SEPARATOR.'usb'.DIRECTORY_SEPARATOR.'devices';
    if (!is_dir($scanRoot) || !is_readable($scanRoot)) {
        throw new GuardianApiException('The USB device inventory cannot be read; device absence cannot be verified.', 503);
    }
    $entries = @scandir($scanRoot);
    if (!is_array($entries)) {
        throw new GuardianApiException('The USB device inventory scan failed; device absence cannot be verified.', 503);
    }
    $originalPort = basename($usbPath);
    $inspected = 0;
    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..'
            || preg_match('/\A(?:usb[0-9]+|[0-9]+-[0-9]+(?:\.[0-9]+)*)\z/D', $entry) !== 1) {
            continue;
        }
        if (hash_equals($originalPort, $entry)) {
            throw new GuardianApiException('A USB device is present again on the original physical port. Run safe eject again.', 409, [
                'reason' => ['code' => 'usb_original_port_reappeared', 'usb_port' => $originalPort],
            ]);
        }
        $entryPath = $scanRoot.DIRECTORY_SEPARATOR.$entry;
        if (!is_dir($entryPath) || !is_readable($entryPath)) {
            throw new GuardianApiException("USB inventory entry {$entry} is unreadable; device absence cannot be verified.", 409);
        }
        ++$inspected;
        $candidateVid = guardian_read_lease_sysfs_attribute($entryPath.DIRECTORY_SEPARATOR.'idVendor', 'idVendor', true);
        $candidatePid = guardian_read_lease_sysfs_attribute($entryPath.DIRECTORY_SEPARATOR.'idProduct', 'idProduct', true);
        if (preg_match('/\A[0-9a-f]{4}\z/D', $candidateVid) !== 1
            || preg_match('/\A[0-9a-f]{4}\z/D', $candidatePid) !== 1) {
            throw new GuardianApiException("USB inventory entry {$entry} has invalid VID/PID; device absence cannot be verified.", 409);
        }
        if (!hash_equals($vid, $candidateVid) || !hash_equals($pid, $candidatePid)) {
            continue;
        }
        $candidateSerial = guardian_lease_usb_serial(guardian_read_lease_sysfs_attribute(
            $entryPath.DIRECTORY_SEPARATOR.'serial',
            'serial',
            false
        ));
        if ($serial === '') {
            throw new GuardianApiException(
                "The completed USB device has no serial number and another {$vid}:{$pid} device is present, so its absence cannot be proven. Disconnect the matching device or run safe eject again after the inventory is unambiguous.",
                409,
                ['reason' => ['code' => 'usb_identity_ambiguous_no_serial', 'usb_vid' => $vid, 'usb_pid' => $pid]]
            );
        }
        if ($candidateSerial === '') {
            throw new GuardianApiException(
                "A live {$vid}:{$pid} USB device has no readable serial number, so the completed device's absence cannot be distinguished safely. Keep the device connected and run safe eject again after the inventory is unambiguous.",
                409,
                ['reason' => ['code' => 'usb_identity_ambiguous_live_serial_missing', 'usb_vid' => $vid, 'usb_pid' => $pid]]
            );
        }
        if ($candidateSerial !== '' && hash_equals($serial, $candidateSerial)) {
            throw new GuardianApiException('The same USB VID/PID/serial identity is present again. Run safe eject again.', 409, [
                'reason' => ['code' => 'usb_identity_reappeared', 'usb_vid' => $vid, 'usb_pid' => $pid, 'usb_serial' => $serial],
            ]);
        }
    }
    if ($inspected === 0) {
        throw new GuardianApiException('The USB device inventory is empty; device absence cannot be proven safely.', 503, [
            'reason' => ['code' => 'usb_inventory_empty'],
        ]);
    }
    clearstatcache(true, $originalPath);
    if (@lstat($originalPath) !== false || file_exists($originalPath) || is_link($originalPath)) {
        throw new GuardianApiException('The original USB sysfs path reappeared during verification. Do not unplug based on the previous approval.', 409, [
            'reason' => ['code' => 'usb_original_path_reappeared_during_lease', 'usb_path' => $usbPath],
        ]);
    }
    $ueventAfter = guardian_read_lease_sysfs_attribute($ueventPath, 'uevent_seqnum', true);
    if (preg_match('/\A[0-9]{1,20}\z/D', $ueventAfter) !== 1 || !hash_equals($ueventBefore, $ueventAfter)) {
        throw new GuardianApiException('The kernel device inventory changed during verification. The safe-to-unplug lease was not renewed; wait for devices to settle and check again.', 409, [
            'reason' => ['code' => 'usb_inventory_changed_during_lease', 'uevent_before' => $ueventBefore, 'uevent_after' => $ueventAfter],
        ]);
    }
}

function guardian_validate_lease_state(
    string $jobId,
    int $generation,
    ?array $authority,
    array $job,
    string $sysRoot = '/sys',
    ?string $currentBootId = null
): array
{
    $bootId = $currentBootId ?? guardian_boot_id();
    if ($generation < 1
        || $authority === null
        || !is_string($authority['job_id'] ?? null)
        || !hash_equals($jobId, $authority['job_id'])
        || !is_int($authority['generation'] ?? null)
        || $generation !== $authority['generation']
        || !is_string($authority['boot_id'] ?? null)
        || $bootId === ''
        || !hash_equals($bootId, $authority['boot_id'])) {
        throw new GuardianApiException('The requested safe-to-unplug lease is no longer the current authority.', 409);
    }
    $identity = guardian_lease_identity_from_job($jobId, $job);
    guardian_assert_lease_usb_absent($identity, $sysRoot);
    return [
        'boot_id' => $authority['boot_id'],
        'authority' => $authority,
        'generation' => $authority['generation'],
        'is_latest_job' => true,
        'job' => [
            'job_id' => $jobId,
            'state' => 'completed',
            'terminal' => true,
            'safe_to_unplug' => true,
        ],
        'device_absent' => true,
        'identity' => $identity,
    ];
}

function guardian_lease(string $jobId, int $generation, string $sysRoot = '/sys'): array
{
    guardian_ensure_runtime_dirs();
    $lockHandle = @fopen(GUARDIAN_RUN_ROOT.'/api.lock', 'c+');
    if ($lockHandle === false || !@flock($lockHandle, LOCK_SH)) {
        if (is_resource($lockHandle)) {
            fclose($lockHandle);
        }
        throw new GuardianApiException('Unable to lock USB Guardian authority state.', 503);
    }
    try {
        $authority = guardian_read_authority();
        $job = guardian_read_lease_job_file($jobId);
        return guardian_validate_lease_state($jobId, $generation, $authority, $job, $sysRoot);
    } finally {
        @flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

function guardian_sanitize_job(array $job): array
{
    $state = strtolower((string)($job['state'] ?? 'unknown'));
    $safeStates = ['completed'];
    $job['safe_to_unplug'] = (($job['safe_to_unplug'] ?? false) === true) && in_array($state, $safeStates, true);
    $job['terminal'] = (($job['terminal'] ?? false) === true) || in_array($state, ['completed', 'failed'], true);
    unset($job['target']);
    if (is_array($job['device'] ?? null)) {
        unset($job['device']['target']);
    }
    return $job;
}

function guardian_expire_queued_job(array $job, string $path): array
{
    if (strtolower((string)($job['state'] ?? '')) !== 'queued' || time() - (int)@filemtime($path) <= 30) {
        return $job;
    }
    $jobId = (string)($job['job_id'] ?? pathinfo($path, PATHINFO_FILENAME));
    guardian_safe_job_file($jobId);
    $failed = [
        'schema_version' => 1,
        'job_id' => $jobId,
        'state' => 'failed',
        'phase' => 'launch',
        'progress' => 0,
        'message' => 'The safe-eject worker did not start within 30 seconds.',
        'error' => 'launch_timeout',
        'reasons' => [[
            'code' => 'launch_timeout',
            'message' => 'The safe-eject worker did not start.',
            'detail' => GUARDIAN_LOG_DIR.'/launcher.log',
            'advice' => 'Download diagnostics and reinstall or restart USB Guardian before retrying.',
        ]],
        'updated_at' => gmdate('c'),
        'safe_to_unplug' => false,
        'terminal' => true,
    ];
    guardian_atomic_json_file($path, $failed);
    guardian_api_log('eject_launch_timeout', ['job_id' => $jobId]);
    return $failed;
}

function guardian_recover_jobs(): void
{
    guardian_core_json([
        'recover',
        '--config', GUARDIAN_CONFIG_FILE,
        '--job-dir', GUARDIAN_JOB_DIR,
        '--log-dir', GUARDIAN_LOG_DIR,
    ], 30);
}

function guardian_active_job_is_stale(array $job, string $path): bool
{
    $state = strtolower((string)($job['state'] ?? ''));
    if (in_array($state, ['queued', 'completed', 'failed'], true) || !is_file($path)) {
        return false;
    }
    return time() - (int)@filemtime($path) > 180;
}

function guardian_has_active_job(): ?array
{
    foreach (glob(GUARDIAN_JOB_DIR.'/*.json') ?: [] as $path) {
        if (is_link($path) || dirname($path) !== GUARDIAN_JOB_DIR) {
            continue;
        }
        $job = json_decode((string)@file_get_contents($path), true);
        if (!is_array($job)) {
            throw new GuardianApiException('An existing safe-eject job state is unreadable. Download diagnostics and reboot before retrying.', 409);
        }
        $job = guardian_expire_queued_job($job, $path);
        if (!in_array(strtolower((string)($job['state'] ?? '')), ['completed', 'failed'], true)) {
            return guardian_sanitize_job($job);
        }
    }
    return null;
}

function guardian_launch_eject(string $token, array $device): array
{
    guardian_ensure_runtime_dirs();
    $lockHandle = @fopen(GUARDIAN_RUN_ROOT.'/api.lock', 'c+');
    if ($lockHandle === false || !@flock($lockHandle, LOCK_EX | LOCK_NB)) {
        if (is_resource($lockHandle)) {
            fclose($lockHandle);
        }
        throw new GuardianApiException('Another USB Guardian request is being started.', 409);
    }
    $authorityWritten = false;
    try {
        guardian_require_not_maintaining();
        guardian_require_runtime();
        guardian_require_enabled();
        $previousAuthority = guardian_read_authority();
        guardian_recover_jobs();
        $active = guardian_has_active_job();
        if ($active !== null) {
            throw new GuardianApiException('Another safe-eject operation is still active.', 409, ['job' => $active]);
        }
        $jobId = guardian_uuid_v4();
        $jobPath = guardian_safe_job_file($jobId);
        $displayName = trim(implode(' ', array_filter([(string)($device['vendor'] ?? ''), (string)($device['model'] ?? '')])));
        if ($displayName === '') {
            $displayName = (string)($device['devX'] ?? ($device['kernel_name'] ?? 'USB device'));
        }
        guardian_atomic_json_file($jobPath, [
            'schema_version' => 1,
            'job_id' => $jobId,
            'state' => 'queued',
            'phase' => 'queued',
            'progress' => 0,
            'message' => 'Safe-eject request queued.',
            'device_name' => $displayName,
            'target_sha256' => hash('sha256', $token),
            'boot_id' => guardian_boot_id(),
            'started_at' => gmdate('c'),
            'updated_at' => gmdate('c'),
            'safe_to_unplug' => false,
            'terminal' => false,
        ]);
        $authority = guardian_next_authority($previousAuthority, $jobId);
        guardian_write_authority($authority);
        $authorityWritten = true;
        if (!is_executable('/usr/bin/setsid')) {
            throw new GuardianApiException('Required process launcher /usr/bin/setsid is unavailable.', 503);
        }
        $launcherLog = GUARDIAN_LOG_DIR.'/launcher.log';
        guardian_rotate_flat_log($launcherLog);
        $command = [
            '/usr/bin/setsid', '--fork', GUARDIAN_BINARY, 'eject',
            '--target', $token,
            '--job-id', $jobId,
            '--job-dir', GUARDIAN_JOB_DIR,
            '--log-dir', GUARDIAN_LOG_DIR,
            '--config', GUARDIAN_CONFIG_FILE,
        ];
        $descriptors = [0 => ['file', '/dev/null', 'r'], 1 => ['file', $launcherLog, 'a'], 2 => ['file', $launcherLog, 'a']];
        $pipes = [];
        $process = @proc_open($command, $descriptors, $pipes, null, null, ['bypass_shell' => true]);
        if (!is_resource($process)) {
            throw new GuardianApiException('Unable to launch safe-eject worker.', 503);
        }
        $exitCode = proc_close($process);
        @chmod($launcherLog, 0600);
        if ($exitCode !== 0) {
            throw new GuardianApiException('Safe-eject worker launcher failed.', 503, ['launcher_exit_code' => $exitCode]);
        }
        guardian_api_log('eject_started', ['job_id' => $jobId, 'device_name' => $displayName, 'target_sha256' => hash('sha256', $token)]);
        return guardian_attach_authority([
            'job_id' => $jobId,
            'state' => 'queued',
            'safe_to_unplug' => false,
            'boot_id' => guardian_boot_id(),
        ], $authority, $jobId);
    } catch (Throwable $exception) {
        $stateFailure = '';
        if (isset($jobId, $jobPath) && is_file($jobPath)) {
            try {
                guardian_atomic_json_file($jobPath, [
                    'schema_version' => 1,
                    'job_id' => $jobId,
                    'state' => 'failed',
                    'phase' => 'launch',
                    'progress' => 0,
                    'message' => $exception->getMessage(),
                    'updated_at' => gmdate('c'),
                    'safe_to_unplug' => false,
                    'terminal' => true,
                ]);
            } catch (Throwable $stateError) {
                $stateFailure = $stateError->getMessage();
                guardian_api_log('eject_launch_failure_state_write_failed', ['job_id' => $jobId, 'message' => $stateFailure]);
            }
        }
        if ($authorityWritten && isset($authority, $jobId)) {
            $status = $exception instanceof GuardianApiException ? $exception->httpStatus : 500;
            $details = $exception instanceof GuardianApiException ? $exception->details : [];
            $details = array_merge($details, guardian_attach_authority(['job_id' => $jobId], $authority, $jobId));
            if ($stateFailure !== '') {
                $details['job_state_error'] = $stateFailure;
            }
            throw new GuardianApiException($exception->getMessage(), $status, $details);
        }
        throw $exception;
    } finally {
        @flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

function guardian_status(string $jobId): array
{
    guardian_ensure_runtime_dirs();
    $lockHandle = @fopen(GUARDIAN_RUN_ROOT.'/api.lock', 'c+');
    if ($lockHandle === false || !@flock($lockHandle, LOCK_SH)) {
        if (is_resource($lockHandle)) {
            fclose($lockHandle);
        }
        throw new GuardianApiException('Unable to lock USB Guardian authority state.', 503);
    }
    try {
        $jobPath = guardian_safe_job_file($jobId);
        try {
            $job = guardian_core_json(['status', '--job-id', $jobId, '--job-dir', GUARDIAN_JOB_DIR, '--json'], 10);
        } catch (GuardianApiException $exception) {
            $job = guardian_read_job_file($jobId);
            if ($job === null) {
                throw $exception;
            }
        }
        $job = guardian_expire_queued_job($job, $jobPath);
        if (guardian_active_job_is_stale($job, $jobPath)) {
            guardian_api_log('stale_job_recovery_started', ['job_id' => $jobId, 'state' => (string)($job['state'] ?? '')]);
            guardian_recover_jobs();
            $recovered = guardian_read_job_file($jobId);
            if ($recovered !== null) {
                $job = $recovered;
            }
        }
        $job['boot_id'] = is_string($job['boot_id'] ?? null) ? $job['boot_id'] : guardian_boot_id();
        return guardian_attach_authority(guardian_sanitize_job($job), guardian_read_authority(), $jobId);
    } finally {
        @flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

function guardian_recent_jobs(): array
{
    guardian_ensure_runtime_dirs();
    $lockHandle = @fopen(GUARDIAN_RUN_ROOT.'/api.lock', 'c+');
    if ($lockHandle === false || !@flock($lockHandle, LOCK_SH)) {
        if (is_resource($lockHandle)) {
            fclose($lockHandle);
        }
        throw new GuardianApiException('Unable to lock USB Guardian authority state.', 503);
    }
    try {
        $authority = guardian_read_authority();
        $paths = glob(GUARDIAN_JOB_DIR.'/*.json') ?: [];
        foreach ($paths as $path) {
            if (is_link($path) || dirname($path) !== GUARDIAN_JOB_DIR) {
                continue;
            }
            $candidate = json_decode((string)@file_get_contents($path), true);
            if (is_array($candidate) && guardian_active_job_is_stale($candidate, $path)) {
                guardian_api_log('stale_job_recovery_started', ['job_id' => (string)($candidate['job_id'] ?? ''), 'state' => (string)($candidate['state'] ?? '')]);
                guardian_recover_jobs();
                break;
            }
        }
        clearstatcache();
        $jobs = [];
        foreach (glob(GUARDIAN_JOB_DIR.'/*.json') ?: [] as $path) {
            if (is_link($path) || dirname($path) !== GUARDIAN_JOB_DIR) {
                continue;
            }
            $job = json_decode((string)@file_get_contents($path), true);
            if (!is_array($job)) {
                continue;
            }
            $job = guardian_expire_queued_job($job, $path);
            $jobId = is_string($job['job_id'] ?? null) ? $job['job_id'] : '';
            $jobs[] = guardian_attach_authority(guardian_sanitize_job($job), $authority, $jobId);
        }
        usort($jobs, static function (array $left, array $right) use ($authority): int {
            $authorityJob = $authority['job_id'] ?? '';
            $leftLatest = ($left['job_id'] ?? '') === $authorityJob;
            $rightLatest = ($right['job_id'] ?? '') === $authorityJob;
            if ($leftLatest !== $rightLatest) {
                return $leftLatest ? -1 : 1;
            }
            $leftTime = strtotime((string)($left['updated_at'] ?? $left['started_at'] ?? '')) ?: 0;
            $rightTime = strtotime((string)($right['updated_at'] ?? $right['started_at'] ?? '')) ?: 0;
            return $rightTime <=> $leftTime ?: strcmp((string)($right['job_id'] ?? ''), (string)($left['job_id'] ?? ''));
        });
        return [
            'jobs' => array_slice($jobs, 0, 50),
            'boot_id' => guardian_boot_id(),
            'authority' => $authority,
            'generation' => $authority['generation'] ?? 0,
            'is_latest_job' => $authority !== null,
        ];
    } finally {
        @flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

function guardian_send_diagnostics(): void
{
    guardian_ensure_runtime_dirs();
    $diagnosticsLock = @fopen(GUARDIAN_RUN_ROOT.'/diagnostics.lock', 'c+');
    if (!is_resource($diagnosticsLock) || !@flock($diagnosticsLock, LOCK_EX | LOCK_NB)) {
        if (is_resource($diagnosticsLock)) {
            fclose($diagnosticsLock);
        }
        throw new GuardianApiException('Another diagnostics archive or log-clear operation is active.', 409);
    }
    $filename = 'usb-guardian-diagnostics-'.gmdate('Ymd-His').'-'.bin2hex(random_bytes(6)).'.zip';
    $output = GUARDIAN_DIAGNOSTIC_DIR.'/'.$filename;
    $result = guardian_run_process([
        GUARDIAN_BINARY, 'diagnostics',
        '--config', GUARDIAN_CONFIG_FILE,
        '--log-dir', GUARDIAN_LOG_DIR,
        '--output', $output,
    ], 180, 1048576);
    if ($result['exit_code'] !== 0 || !is_file($output) || is_link($output)) {
        @unlink($output);
        guardian_api_log('diagnostics_failed', ['exit_code' => $result['exit_code'], 'stderr' => substr(trim($result['stderr']), 0, 2000)]);
        throw new GuardianApiException('Unable to create diagnostics archive.', 503);
    }
    $realOutput = realpath($output);
    $realDirectory = realpath(GUARDIAN_DIAGNOSTIC_DIR);
    $size = filesize($output);
    $handle = @fopen($output, 'rb');
    $magic = $handle !== false ? (string)fread($handle, 2) : '';
    if ($handle !== false) {
        fclose($handle);
    }
    if ($realOutput === false || $realDirectory === false || dirname($realOutput) !== $realDirectory || $magic !== 'PK' || $size === false || $size < 22 || $size > 268435456) {
        @unlink($output);
        throw new GuardianApiException('Diagnostics archive validation failed.', 503);
    }
    guardian_api_log('diagnostics_downloaded', ['filename' => $filename, 'bytes' => $size]);
    header('Content-Type: application/zip');
    header('Content-Length: '.(string)$size);
    header('Content-Disposition: attachment; filename="'.$filename.'"');
    header('Cache-Control: no-store, max-age=0');
    header('X-Content-Type-Options: nosniff');
    register_shutdown_function(static function () use ($output): void {
        @unlink($output);
    });
    readfile($output);
    @unlink($output);
    exit;
}

function guardian_maintenance_prepare(string $runRoot = GUARDIAN_RUN_ROOT, string $logRoot = GUARDIAN_LOG_DIR): void
{
    $api = @fopen($runRoot.'/api.lock', 'c+');
    if (!is_resource($api) || !flock($api, LOCK_EX | LOCK_NB)) {
        if (is_resource($api)) fclose($api);
        throw new RuntimeException('A safe-eject request is starting. Wait for it to finish.');
    }
    $transaction = null;
    try {
        $transaction = @fopen($logRoot.'/.transaction.lock', 'c+');
        if (!is_resource($transaction) || !flock($transaction, LOCK_EX | LOCK_NB)) {
            throw new RuntimeException('A safe-eject transaction is active. Wait for it to finish.');
        }
        foreach (glob($runRoot.'/jobs/*.json') ?: [] as $path) {
            $job = is_link($path) ? null : json_decode((string)@file_get_contents($path), true);
            if (!is_array($job) || !in_array($job['state'] ?? '', ['completed', 'failed'], true)) {
                throw new RuntimeException('A queued, active or unreadable safe-eject job is present.');
            }
        }
        if ((glob($logRoot.'/transactions/*/active.json') ?: []) || (glob($runRoot.'/ud-adapter/*') ?: [])) {
            throw new RuntimeException('Safe-eject recovery state is present. Finish recovery before updating or removing UD.');
        }
        if (@file_put_contents($runRoot.'/maintenance', 'maintenance', LOCK_EX) === false) {
            throw new RuntimeException('Unable to enter safe-eject maintenance mode.');
        }
    } finally {
        if (is_resource($transaction)) { flock($transaction, LOCK_UN); fclose($transaction); }
        flock($api, LOCK_UN);
        fclose($api);
    }
}
