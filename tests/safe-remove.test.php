<?php
namespace UDRemoveTest;
/* Run with: php tests/safe-remove.test.php. Fixtures never access a real disk. */
$plugin = dirname(__DIR__).'/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices';
eval('namespace '.__NAMESPACE__.';'.substr(file_get_contents($plugin.'/include/SafeRemove.php'), 5));
$rc = file_get_contents($plugin.'/scripts/rc.unassigned');
// The checkout uses CRLF; normalize only the test's in-memory source.
$rc = str_replace("\r\n", "\n", $rc);
$start = strpos($rc, 'function unassigned_detach(');
$end = strpos($rc, "\n}\n", $start);
eval('namespace '.__NAMESPACE__.';'.substr($rc, $start, $end - $start + 2));
$lib = str_replace("\r\n", "\n", file_get_contents($plugin.'/include/lib.php'));
foreach (['format_disk', 'remove_partition', 'remove_all_partitions', 'do_mount'] as $function) {
	$start = strpos($lib, 'function '.$function.'(');
	$end = strpos($lib, "\n}\n", $start);
	eval('namespace '.__NAMESPACE__.';'.substr($lib, $start, $end - $start + 2));
}
$root = sys_get_temp_dir().'/ud-remove-'.bin2hex(random_bytes(6));
$checks = 0;
function check($actual, $expected, $name) {
	global $checks;
	if ($actual !== $expected) throw new \RuntimeException("$name: expected '$expected', got '$actual'");
	$checks++;
}
function put($path, $text) {
	if (! is_dir(dirname($path))) mkdir(dirname($path), 0700, true);
	file_put_contents($path, $text);
}
function cleanup($dir) {
	foreach (scandir($dir) as $name) {
		if ($name === '.' || $name === '..') continue;
		$path = "$dir/$name";
		is_dir($path) ? cleanup($path) : unlink($path);
	}
	rmdir($dir);
}
/* Mock OS calls in an isolated namespace; production code runs unchanged. */
class MiscUD {
	static function base_device($name) { return preg_replace('/[0-9]+/', '', $name); }
}
$io = [];
function mapped($path) {
	global $root;
	$path = str_replace('/sys/block/', '/sys/class/block/', $path);
	return preg_match('#^/(sys|proc|dev|var/lock|tmp)/#', $path) ? $root.$path : $path;
}
function file_get_contents($p) { return \file_get_contents(mapped($p)); }
function file($p, $flags = 0) { return \file(mapped($p), $flags); }
function is_file($p) { return \is_file(mapped($p)); }
function is_dir($p) {
	global $io;
	if ($p === '/sys/block/sdb' && !empty($io['deleted']) && empty($io['timeout'])) return false;
	return \is_dir(mapped($p));
}
function file_exists($p) {
	global $io;
	if ($p === '/dev/sdb' && !empty($io['deleted']) && empty($io['timeout'])) return false;
	return \file_exists(mapped($p));
}
function realpath($p) {
	$resolved = \realpath(mapped($p));
	return strpos($p, '/dev/') === 0 && $resolved ? $p : $resolved;
}
function scandir($p) { return \scandir(mapped($p)); }
function glob($p) { return \glob(mapped($p)); }
function fopen($p, $mode) { return \fopen(mapped($p), $mode); }
function fwrite($handle, $text) {
	global $io;
	$path = stream_get_meta_data($handle)['uri'];
	if (substr($path, -14) === '/device/delete') {
		$io['writes']++;
		if (!empty($io['write_error'])) return false;
		$io['deleted'] = true;
	}
	return \fwrite($handle, $text);
}
function sleep($seconds) { return 0; }
function usleep($microseconds) { }
function proc_open($args, $descriptors, &$pipes) {
	global $io;
	check(array_slice($args, 1), ['/dev/sdb', '123'], 'claim receives device and disk sequence');
	check(basename($args[0]), 'usb-device-claim', 'native exclusive helper');
	$pipes = [tmpfile(), tmpfile(), tmpfile()];
	$message = !empty($io['exclusive_busy']) ? 'busy' : (!empty($io['fsync_error']) ? 'flush' : 'ready');
	if (empty($io['exclusive_timeout'])) { \fwrite($pipes[1], $message."\n"); rewind($pipes[1]); }
	return tmpfile();
}
function proc_get_status($handle) {
	global $io;
	return ['pid' => 42, 'running' => empty($io['exclusive_busy']), 'exitcode' => 1];
}
function proc_close($handle) { fclose($handle); return 0; }
function proc_terminate($handle) { return true; }
function unassigned_log($text) { }
function get_all_disks_info() {
	global $disk, $io;
	$io['scans']++;
	return [array_replace($disk, ($io['scans'] > 1 ? ($io['second_scan'] ?? []) : []))];
}
function exec($cmd, &$out, &$status) {
	global $io;
	$out = [];
	if (strpos($cmd, '/fuser ') !== false) {
		$status = !empty($io['raw_busy']) && strpos($cmd, '/fuser --') !== false ? 0 : ($io['fuser'] ?? 1);
	} elseif (strpos($cmd, '/blockdev --flushbufs ') !== false) {
		$io['flushes']++;
		$status = $io['flush'] ?? 0;
	} else {
		throw new \RuntimeException('Unexpected external command: '.$cmd);
	}
}
function parse_ini_file($path, $sections = false, $mode = INI_SCANNER_NORMAL) {
	if ($path === '/var/local/emhttp/var.ini') return ['csrf_token' => 'expected-token'];
	return \parse_ini_file($path, $sections, $mode);
}
function shell_exec($cmd) { return '{"success":true,"reason":""}'; }
function do_mount_local($info) { return false; }
$sys = "$root/sys";
$proc = "$root/proc";
$block = "$sys/class/block/sdb";
$disk = ['device' => '/dev/sdb', 'serial' => 'USB_TEST', 'id_bus' => 'usb',
	'partitions' => [['device' => '/dev/sdb1', 'fstype' => 'ext4', 'label' => 'DATA']]];
$inspect = fn($d = null, $serial = 'USB_TEST', $seq = '123') =>
	ud_usb_remove_check($d ?? $disk, $serial, $seq, $sys, $proc);
try {
	/* Model a single USB mass-storage disk with one partition. */
	put("$sys/class/idVendor", '1234');
	put("$sys/class/remove", '');
	put("$sys/class/interface0/bInterfaceClass", "08\n");
	put("$block/diskseq", "123\n");
	put("$block/dev", "8:16\n");
	put("$block/sdb1/dev", "8:17\n");
	put("$block/sdb1/partition", '1');
	mkdir("$block/holders");
	mkdir("$block/sdb1/holders");
	put("$proc/1/mountinfo", "1 0 0:1 / / rw - rootfs rootfs rw\n");
	put("$proc/swaps", "Filename Type Size Used Priority\n");
	check($inspect(), '', 'idle single USB disk');
	check($inspect(null, 'OTHER'), 'changed', 'stale serial');
	check($inspect(null, 'USB_TEST', '124'), 'changed', 'reused kernel name');
	check($inspect(null, 'USB_TEST', ''), 'changed', 'missing disk sequence');
	check($inspect(array_replace($disk, ['id_bus' => 'ata'])), 'unsupported', 'non-USB');
	check($inspect(array_replace($disk, ['device' => '/dev/sdb1'])), 'unsupported', 'partition request');
	foreach (['array_disk', 'pool_disk', 'pass_through', 'mounted', 'mounting', 'unmounting',
		'preclearing', 'clearing', 'formatting', 'running', 'not_unmounted'] as $flag) {
		check($inspect(array_replace($disk, [$flag => true])), 'busy', $flag);
	}
	$part = $disk;
	$part['partitions'][0]['label'] = 'UNRAID';
	check($inspect($part), 'protected', 'boot label');
	foreach (['crypto_LUKS', 'zfs', 'zfs_member', 'btrfs', 'apfs'] as $fs) {
		$part['partitions'][0] = ['device' => '/dev/sdb1', 'fstype' => $fs];
		check($inspect($part), 'unsupported', $fs);
		check($inspect(array_replace($disk, ['fstype' => $fs])), 'unsupported', 'whole-disk '.$fs);
	}
	check($inspect(array_replace($disk, ['not_udev' => true])), 'inspection', 'stale disk metadata');
	$part = $disk;
	$part['partitions'][0]['not_udev'] = true;
	check($inspect($part), 'inspection', 'stale partition metadata');
	$part['partitions'][0] = [];
	check($inspect($part), 'inspection', 'missing partition metadata');
	$part['partitions'] = [];
	check($inspect($part), 'inspection', 'undiscovered kernel partition');
	$part['partitions'][0] = ['device' => '/dev/sdb2', 'fstype' => 'ext4'];
	check($inspect($part), 'inspection', 'partition identity mismatch');
	$part['partitions'][0] = ['device' => '/dev/sdb1', 'fstype' => 'ext4', 'file_system' => 'btrfs'];
	check($inspect($part), 'unsupported', 'unsupported live filesystem');
	put("$block/sdb1/holders/dm-0", '');
	check($inspect(), 'busy', 'device-mapper holder');
	unlink("$block/sdb1/holders/dm-0");
	put("$proc/99/mountinfo", "9 1 8:17 / /container/bind rw - ext4 /dev/sdb1 rw\n");
	check($inspect(), 'mounted', 'container bind mount');
	cleanup("$proc/99");
	put("$proc/1/mountinfo", "2 1 8:16 / /boot rw - vfat /dev/sdb rw\n");
	check($inspect(), 'mounted', 'whole-disk boot filesystem');
	put("$proc/1/mountinfo", "1 0 0:1 / / rw - rootfs rootfs rw\n");
	put("$sys/class/block/sdc/dev", '8:32');
	check($inspect(), 'unsupported', 'second disk in enclosure');
	cleanup("$sys/class/block/sdc");
	put("$sys/class/interface1/bInterfaceClass", '03');
	check($inspect(), 'unsupported', 'composite USB device');
	cleanup("$sys/class/interface1");
	unlink("$proc/swaps");
	check($inspect(), 'inspection', 'unreadable swap state');
	put("$proc/swaps", "Filename Type Size Used Priority\n");
	put("$proc/1/mountinfo", "invalid\n");
	check($inspect(), 'inspection', 'malformed mount state');
	/* Exercise the real safe-remove and detach functions with mocked OS effects. */
	put("$proc/1/mountinfo", "1 0 0:1 / / rw - rootfs rootfs rw\n");
	put("$block/device/delete", '');
	put("$root/dev/sdb", '');
	mkdir("$root/var/lock", 0700, true);
	$cases = [
		[[], '', 1],
		[['fuser' => 0], 'busy', 0],
		[['fuser' => 124], 'inspection', 0],
		[['raw_busy' => true], 'busy', 0],
		[['fuser' => 127], 'inspection', 0],
		[['flush' => 1], 'flush', 0],
		[['fsync_error' => true], 'flush', 0],
		[['second_scan' => ['mounted' => true]], 'busy', 0],
		[['second_scan' => ['serial' => 'REPLACEMENT']], 'changed', 0],
		[['second_scan' => ['not_udev' => true]], 'inspection', 0],
		[['second_scan' => ['partitions' => []]], 'inspection', 0],
		[['exclusive_busy' => true], 'busy', 0],
		[['exclusive_timeout' => true], 'inspection', 0],
		[['write_error' => true], 'detach', 1],
		[['timeout' => true], 'detach', 1]
	];
	foreach ($cases as [$fault, $reason, $writes]) {
		$io = array_merge(['scans' => 0, 'writes' => 0, 'flushes' => 0], $fault);
		check(ud_safe_remove_usb('/dev/sdb', 'USB_TEST', '123'), $reason, 'pipeline '.json_encode($fault));
		check($io['writes'], $writes, 'no removal before checks pass');
		$lock = \fopen("$root/var/lock/unassigned.devices-sdb.lock", 'c');
		check(flock($lock, LOCK_EX | LOCK_NB), true, 'operation lock released on every exit');
		fclose($lock);
	}
	$lock = \fopen("$root/var/lock/unassigned.devices-sdb.lock", 'c');
	flock($lock, LOCK_EX);
	check(ud_safe_remove_usb('/dev/sdb', 'USB_TEST', '123'), 'busy', 'concurrent operation');
	check(format_disk('/dev/sdb', 'ext4', '', ''), false, 'format honors removal lock');
	check(remove_partition('/dev/sdb', '1'), false, 'partition removal honors removal lock');
	check(remove_all_partitions('/dev/sdb'), false, 'disk clearing honors removal lock');
	check(do_mount(['device' => '/dev/sdb1', 'fstype' => 'ext4']), false, 'partition mount honors disk lock');
	check(do_mount(['device' => '/dev/mapper/test', 'luks' => '/dev/sdb1', 'fstype' => 'crypto_LUKS']), false, 'encrypted mount honors physical disk lock');
	fclose($lock);
	$disk['partitions'][0]['target'] = '/busy';
	$disk['partitions'][0]['part'] = '1';
	$io = ['scans' => 0];
	foreach ([
		fn() => format_disk('/dev/sdb', 'ext4', '', ''),
		fn() => remove_partition('/dev/sdb', '1'),
		fn() => remove_all_partitions('/dev/sdb'),
		fn() => do_mount(['device' => '/dev/sdb1', 'fstype' => 'ext4'])
	] as $operation) {
		check($operation(), false, 'native operation failure');
		$lock = \fopen("$root/var/lock/unassigned.devices-sdb.lock", 'c');
		check(flock($lock, LOCK_EX | LOCK_NB), true, 'native operation releases lock on failure');
		fclose($lock);
	}
	check(ud_device_operation_lock('/dev/sdb'), true, 'outer operation lock');
	check(ud_device_operation_lock('/dev/sdb1'), true, 'nested partition operation lock');
	ud_device_operation_lock('/dev/sdb1', true);
	$lock = \fopen("$root/var/lock/unassigned.devices-sdb.lock", 'c');
	check(flock($lock, LOCK_EX | LOCK_NB), false, 'nested release retains outer lock');
	ud_device_operation_lock('/dev/sdb', true);
	check(flock($lock, LOCK_EX | LOCK_NB), true, 'outer release frees lock');
	fclose($lock);
	/* Execute the actual native endpoint's new case, including its CSRF gate. */
	define(__NAMESPACE__.'\DOCROOT', '/mock');
	define(__NAMESPACE__.'\UNASSIGNED_PLUGIN', 'unassigned.devices');
	$endpoint = file_get_contents($plugin.'/include/UnassignedDevices.php');
	$start = strpos($endpoint, "\tcase 'safe_remove':");
	$end = strpos($endpoint, "\tcase 'umount':", $start);
	foreach (['' => false, 'wrong-token' => false, 'expected-token' => true] as $token => $allowed) {
		$_POST = ['csrf_token' => $token, 'device' => '/dev/sdb', 'serial' => 'USB_TEST', 'sequence' => '123'];
		http_response_code(200);
		ob_start();
		eval('namespace '.__NAMESPACE__."; switch ('safe_remove') {".substr($endpoint, $start, $end - $start).'}');
		$response = json_decode(ob_get_clean(), true);
		check($response['success'], $allowed, 'CSRF '.($token ?: 'missing'));
		check(http_response_code(), $allowed ? 200 : 403, 'HTTP status');
	}
	/* Verify every new source string has a separate Simplified Chinese entry. */
	$page = file_get_contents($plugin.'/DeviceSettings.page');
	$start = strpos($page, 'function safe_remove_usb(button)');
	$end = strpos($page, '/* Detach a disk device. */', $start);
	$js = substr($page, $start, $end - $start);
	preg_match_all("/'[a-z]+' => '([^']+)'/", $js, $matches);
	$zh = parse_ini_file($plugin.'/language/zh_CN/safe_remove.txt', false, INI_SCANNER_RAW);
	foreach (array_merge($matches[1], ['Safe Remove', 'Unmount the USB disk first, then use Safe Remove and wait for confirmation before unplugging it.']) as $english) {
		$key = str_replace(['?', '.'], '', $english);
		check(isset($zh[$key]) && preg_match('/\p{Han}/u', $zh[$key]) === 1, true, "Chinese: $key");
		check(preg_match('/\p{Han}/u', $english), 0, "English: $key");
	}
	echo "$checks safe-removal and language checks passed\n";
} finally {
	cleanup($root);
}
