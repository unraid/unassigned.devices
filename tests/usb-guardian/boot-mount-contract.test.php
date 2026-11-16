<?php
declare(strict_types=1);

require_once __DIR__.'/../../source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/include/api_helpers.php';

function boot_mount_line(string $root, string $mountPoint, string $options, string $fstype, string $source): string
{
    return "42 31 8:1 {$root} {$mountPoint} {$options} - {$fstype} {$source} rw\n";
}

function boot_expect(bool $expected, string $fixture, string $message): void
{
    $status = guardian_boot_mount_status_from_mountinfo($fixture);
    if (($status['ok'] ?? false) !== $expected) {
        throw new RuntimeException($message.' Status: '.json_encode($status));
    }
}

$root = boot_mount_line('/', '/', 'rw,relatime', 'tmpfs', 'rootfs');
boot_expect(false, $root, 'A missing separate /boot mount must fail.');
boot_expect(true, $root.boot_mount_line('/', '/boot', 'rw,nosuid,nodev', 'vfat', '/dev/sda1'), 'A writable VFAT boot flash must pass.');
boot_expect(true, $root.boot_mount_line('/', '/boot', 'rw', 'msdos', '/dev/disk/by-label/UNRAID'), 'An msdos boot flash via /dev must pass.');
boot_expect(false, $root.boot_mount_line('/', '/boot', 'rw', 'tmpfs', 'tmpfs'), 'A tmpfs /boot must fail.');
boot_expect(false, $root.boot_mount_line('/', '/boot', 'ro', 'vfat', '/dev/sda1'), 'A read-only boot flash must fail.');
boot_expect(false, $root.boot_mount_line('/config', '/boot', 'rw', 'vfat', '/dev/sda1'), 'A subdirectory mount must fail.');
boot_expect(false, $root.boot_mount_line('/', '/boot', 'rw', 'vfat', '/dev/sda1').boot_mount_line('/', '/boot', 'rw', 'vfat', '/dev/sdb1'), 'Stacked /boot mounts must fail.');
boot_expect(false, "malformed\n", 'Malformed mountinfo must fail.');
boot_expect(false, $root.boot_mount_line('/', '/boot', 'rw', 'vfat', '/dev/sda1').boot_mount_line('/', '/boot/config', 'rw', 'tmpfs', 'tmpfs'), 'A mount above the plugin directory must fail.');
boot_expect(false, $root.boot_mount_line('/', '/boot', 'rw', 'vfat', '/dev/sda1').boot_mount_line('/', '/boot/config/plugins/unassigned.devices/usb-guardian/logs/transactions', 'rw', 'tmpfs', 'tmpfs'), 'A mount inside the plugin persistent directory must fail.');
boot_expect(true, $root.boot_mount_line('/', '/boot', 'rw', 'vfat', '/dev/sda1').boot_mount_line('/', '/boot/other', 'rw', 'tmpfs', 'tmpfs'), 'An unrelated /boot child mount must not block logging.');

$escaped = $root.boot_mount_line('/', '/boot\\040flash', 'rw', 'vfat', '/dev/sda1');
boot_expect(false, $escaped, 'An escaped non-/boot mount point must not be accepted.');

echo "USB Guardian boot-mount contract tests passed.\n";
