<?php
/* USB removal uses UD's existing disk discovery and detach implementation. */

/* Keep UD mount/format/clear operations out of the final removal window. */
function ud_device_operation_lock($device, $release = false) {
	static $locks = [];
	$device = realpath($device) ?: $device;
	if (! preg_match('#^/dev/(sd[a-z]+)[0-9]*$#D', $device, $match)) return true;
	$dev = $match[1];
	if ($release) {
		if (isset($locks[$dev]) && --$locks[$dev]['count'] === 0) {
			fclose($locks[$dev]['handle']);
			unset($locks[$dev]);
		}
		return true;
	}
	if (isset($locks[$dev])) {
		$locks[$dev]['count']++;
		return true;
	}
	$lock = @fopen('/var/lock/unassigned.devices-'.$dev.'.lock', 'ce');
	if (! $lock || ! flock($lock, LOCK_EX | LOCK_NB)) {
		if ($lock) fclose($lock);
		unassigned_log("Device '/dev/$dev' has another operation in progress.");
		return false;
	}
	$locks[$dev] = ['handle' => $lock, 'count' => 1];
	return true;
}

/* Return a reason code; never infer safety just from UD's cached mounted flag. */
function ud_usb_remove_check($disk, $serial, $sequence, $sys = '/sys', $proc = '/proc') {
	$dev = basename($disk['device'] ?? '');
	if (! preg_match('/^sd[a-z]+$/D', $dev) || ($disk['id_bus'] ?? '') != 'usb') return 'unsupported';
	if (! $serial || ($disk['serial'] ?? '') !== $serial) return 'changed';
	$block = "$sys/class/block/$dev";
	$actual = trim(@file_get_contents("$block/diskseq") ?: '');
	if (! ctype_digit($sequence) || $actual !== $sequence) return 'changed';
	foreach (['array_disk', 'pool_disk', 'pass_through', 'preclearing', 'formatting', 'clearing',
		'mounting', 'unmounting', 'running', 'mounted', 'not_unmounted'] as $flag) {
		if (! empty($disk[$flag])) return 'busy';
	}
	foreach ($disk['partitions'] ?? [] as $part) {
		if (($part['label'] ?? '') === 'UNRAID' || ! empty($part['array_disk'])) return 'protected';
		if (! empty($part['pool']) || ! empty($part['running']) ||
			in_array($part['fstype'] ?? '', ['crypto_LUKS', 'zfs', 'btrfs', 'apfs'])) return 'unsupported';
	}
	if (in_array($disk['fstype'] ?? '', ['crypto_LUKS', 'zfs', 'btrfs', 'apfs'])) return 'unsupported';
	$usb = realpath($block);
	while ($usb && $usb !== dirname($usb) && ! is_file("$usb/idVendor")) $usb = dirname($usb);
	if (! $usb || ! is_file("$usb/idVendor") || ! is_file("$usb/remove")) return 'unsupported';
	/* A USB enclosure/composite device may contain another disk or another function. */
	$interfaces = glob("$usb/*/bInterfaceClass");
	if (! $interfaces) return 'unsupported';
	foreach ($interfaces as $interface) {
		if (trim(@file_get_contents($interface) ?: '') !== '08') return 'unsupported';
	}
	foreach (glob("$sys/class/block/*") ?: [] as $other) {
		$path = realpath($other);
		if ($path && strpos($path, $usb.DIRECTORY_SEPARATOR) === 0 && ! is_file("$other/partition") && basename($other) !== $dev) return 'unsupported';
	}
	$nodes = [$block];
	foreach (glob("$block/$dev*") ?: [] as $part) {
		if (is_file("$part/partition")) $nodes[] = $part;
	}
	$numbers = [];
	foreach ($nodes as $node) {
		$number = trim(@file_get_contents("$node/dev") ?: '');
		$holders = @scandir("$node/holders");
		if (! preg_match('/^\d+:\d+$/D', $number) || $holders === false) return 'inspection';
		if (array_diff($holders, ['.', '..'])) return 'busy';
		$numbers[] = $number;
	}
	/* Check every process mount namespace, including bind mounts and containers. */
	$mounts = glob("$proc/[0-9]*/mountinfo");
	if (! $mounts) return 'inspection';
	foreach ($mounts as $mount) {
		$lines = @file($mount, FILE_IGNORE_NEW_LINES);
		if ($lines === false) {
			if (is_dir(dirname($mount))) return 'inspection';
			continue; // A process may have exited during the scan.
		}
		foreach ($lines as $line) {
			$fields = explode(' ', $line);
			if (count($fields) < 10) return 'inspection';
			if (in_array($fields[2], $numbers, true)) return 'mounted';
		}
	}
	$swaps = @file("$proc/swaps", FILE_IGNORE_NEW_LINES);
	if ($swaps === false) return 'inspection';
	foreach (array_slice($swaps, 1) as $swap) {
		$source = realpath(preg_split('/\s+/', trim($swap))[0]);
		$stat = $source ? @stat($source) : false;
		if ($stat === false) return 'inspection';
		$number = ($stat['mode'] & 0170000) === 0060000 ? $stat['rdev'] : $stat['dev'];
		$major = (($number >> 8) & 0xfff) | (($number >> 32) & 0xfffff000);
		$minor = ($number & 0xff) | (($number >> 12) & 0xffffff00);
		if (in_array("$major:$minor", $numbers, true)) return 'busy';
	}
	return '';
}

/* Called by rc.unassigned, so the original detach and logging paths are reused. */
function ud_safe_remove_usb($device, $serial, $sequence) {
	if (! preg_match('#^/dev/sd[a-z]+$#D', $device) || ! ud_device_operation_lock($device)) return 'busy';
	$claim = false;
	$pipes = [];
	try {
		$find = function () use ($device) {
			foreach (get_all_disks_info() as $disk) {
				if (($disk['device'] ?? '') === $device) return $disk;
			}
			return [];
		};
		for ($pass = 0; $pass < 2; $pass++) {
			clearstatcache();
			if (is_file('/tmp/unassigned.devices/shut_down')) return 'busy';
			if ($reason = ud_usb_remove_check($find(), $serial, $sequence)) return $reason;
			$dev = basename($device);
			$nodes = [$device];
			foreach (glob("/sys/class/block/$dev/$dev*") ?: [] as $part) {
				if (is_file("$part/partition")) $nodes[] = '/dev/'.basename($part);
			}
			/* fuser -m also catches files on a lazily unmounted filesystem, e.g. shfs. */
			$args = implode(' ', array_map('escapeshellarg', $nodes));
			$raw = $nodes;
			foreach (['scsi_generic' => '/dev/', 'bsg' => '/dev/bsg/'] as $type => $prefix) {
				foreach (glob("/sys/class/block/$dev/device/$type/*") ?: [] as $node) $raw[] = $prefix.basename($node);
			}
			foreach (['-m -- '.$args, '-- '.implode(' ', array_map('escapeshellarg', $raw))] as $probe) {
				$output = [];
				exec('/usr/bin/timeout 5 /usr/bin/fuser '.$probe.' 2>&1', $output, $status);
				if ($status === 0) return 'busy';
				if ($status !== 1 || trim(implode("\n", $output)) !== '') return 'inspection';
			}
			if ($pass === 0) {
				/* Flush block buffers before removal; never offline the SCSI device first. */
				exec('/usr/bin/timeout 15 /sbin/blockdev --flushbufs '.$args.' 2>&1', $output, $status);
				if ($status !== 0) return 'flush';
				$buffer = @fopen($device, 'r+');
				$flushed = $buffer && function_exists('fsync') && @fsync($buffer);
				if ($buffer) fclose($buffer);
				if (! $flushed) return 'flush';
			}
		}
		/* dd opens with O_EXCL but receives no input, so it writes no data. nocreat
		 * and notrunc are essential. Keep stdin open to hold the kernel claim until
		 * detach completes, including mounts in namespaces without a live process. */
		$claim = @proc_open(['/bin/dd', 'of='.$device, 'oflag=excl,nocreat,nonblock', 'conv=notrunc', 'status=none'],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		if (! is_resource($claim)) return 'inspection';
		$ready = false;
		for ($i = 0; $i < 200; $i++) {
			$state = proc_get_status($claim);
			if (! $state['running']) return $state['exitcode'] === 1 ? 'busy' : 'inspection';
			if (@readlink('/proc/'.$state['pid'].'/fd/1') === $device) {
				$ready = true;
				break;
			}
			usleep(10000);
		}
		if (! $ready) return 'inspection';
		return unassigned_detach($device, true, $sequence) ? '' : 'detach';
	} finally {
		// Closing an empty stdin supplies EOF; no bytes are ever sent to the disk.
		foreach ($pipes as $pipe) if (is_resource($pipe)) fclose($pipe);
		if (is_resource($claim)) proc_close($claim);
		ud_device_operation_lock($device, true);
	}
}
