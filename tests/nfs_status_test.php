<?php
/* SPDX-License-Identifier: GPL-2.0-or-later
 * Local regression harness: executes the actual upstream function bodies with
 * simulated network and state dependencies. No Unraid services are contacted. */
namespace UDNfsRegression;

const NFS_PORT = '2049';
const SMB_PORT = '445';
const RPC_PORT = '111';

class MiscUD {
	public static $state = [];
	public static function get_json($path) { return self::$state; }
	public static function save_json($path, $state) { self::$state = $state; }
	public static function is_ip($host) { return filter_var($host, FILTER_VALIDATE_IP) !== false; }
}

function is_server_alive($server, $port) {
	$GLOBALS['ports_checked'][] = $port;
	return $GLOBALS['port_up'];
}
function shell_exec($command) {
	$GLOBALS['shell_calls'][] = $command;
	throw new \RuntimeException('Unexpected legacy probe: '.$command);
}
function timed_exec($seconds, $command) {
	$GLOBALS['diagnostic_calls'][] = [$seconds, $command];
	return $GLOBALS['rpc_output'];
}
function unassigned_log($message) {}

function loadFunction($source, $name) {
	$tokens = token_get_all($source);
	foreach ($tokens as $i => $token) {
		if (!is_array($token) || $token[0] !== T_FUNCTION) { continue; }
		$j = $i + 1;
		while (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) { $j++; }
		if (!is_array($tokens[$j]) || $tokens[$j][1] !== $name) { continue; }
		$code = '';
		$depth = 0;
		$started = false;
		for (; $i < count($tokens); $i++) {
			$t = $tokens[$i];
			$code .= is_array($t) ? $t[1] : $t;
			if ($t === '{') { $depth++; $started = true; }
			if ($t === '}' && --$depth === 0 && $started) {
				eval('namespace UDNfsRegression; '.$code);
				return;
			}
		}
	}
	throw new \RuntimeException('Function not found: '.$name);
}

function check($condition, $message) {
	if (!$condition) { throw new \RuntimeException($message); }
	$GLOBALS['checks']++;
}
function resetCase($up = true, $diagnostic = false) {
	MiscUD::$state = [];
	$GLOBALS['port_up'] = $up;
	$GLOBALS['remote_test'] = $diagnostic;
	$GLOBALS['ports_checked'] = [];
	$GLOBALS['shell_calls'] = [];
	$GLOBALS['diagnostic_calls'] = [];
	$GLOBALS['rpc_output'] = '';
}
function capture($fn) {
	ob_start();
	try { $result = $fn(); return [$result, ob_get_contents()]; }
	finally { ob_end_clean(); }
}

$repo = $argv[1] ?? dirname(__DIR__);
$path = $repo.'/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/scripts/get_ud_stats';
$source = file_get_contents($path);
loadFunction($source, 'is_server_online');
loadFunction($source, 'getSupportedNFSVersions');
$tc = '/unused-test-state';
$local_tld = 'LOCAL';
$checks = 0;

// This is the original failure: NFS is reachable, legacy discovery is unavailable.
resetCase();
check(is_server_online('192.0.2.10', 'NFS') === true, 'NFSv4-only server must allow a mount attempt');
check(MiscUD::$state['192.0.2.10.NFS']['online'] === 'yes', 'Reachable status must be persisted for automount and stats');
check($ports_checked === [NFS_PORT], 'Only the NFS port should be required');
check($shell_calls === [], 'Normal NFS status must not invoke showmount or rpcinfo');

// A listening port is reachability, not proof of authorization or an export.
resetCase(true, true);
[$reachable, $text] = capture(fn() => is_server_online('192.0.2.10', 'NFS'));
check($reachable && str_contains($text, 'required to verify access'), 'Diagnostic must distinguish reachability from share access');
check($shell_calls === [], 'NFS diagnostics must not require a mountd response');

// A genuinely unreachable server stays offline; retain existing debounce behavior.
resetCase(false);
check(is_server_online('192.0.2.10', 'NFS') === false, 'Closed port must remain offline');
resetCase(false);
MiscUD::$state['192.0.2.10.NFS'] = ['online' => 'yes', 'no_pings' => 0];
for ($i = 0; $i < 3; $i++) {
	check(is_server_online('192.0.2.10', 'NFS') === true, 'Preserve existing offline grace period');
}
check(is_server_online('192.0.2.10', 'NFS') === false, 'Repeated failure must eventually mark server offline');

// Other protocols keep using their own ports.
resetCase();
check(is_server_online('192.0.2.10', 'SMB') === true, 'SMB reachability regression');
check($ports_checked === [SMB_PORT], 'SMB must use port 445');
resetCase(false);
check(is_server_online('192.0.2.10', 'RPC') === false, 'RPC failure must stay independent of NFS');
check($ports_checked === [RPC_PORT], 'RPC diagnostic must use port 111');

// Real rpcinfo -p columns, with or without indentation, must be parsed correctly.
resetCase();
$rpc_output = "   program vers proto   port  service\n    100003  3 tcp 2049 nfs\n100003 4 tcp 2049 nfs\n100003 4 udp 2049 nfs\n100005 3 tcp 20048 mountd\n";
[$registered, $text] = capture(fn() => getSupportedNFSVersions('192.0.2.10'));
check($registered && str_contains($text, '3, 4'), 'RPC registration parsing must handle normal whitespace and deduplicate versions');
check(!str_contains($text, '3, 4, 4'), 'Duplicate transport registrations must not duplicate versions');
check($diagnostic_calls[0][0] === 5, 'Optional RPC diagnostic must have a bounded timeout');
check(str_contains($diagnostic_calls[0][1], '/sbin/rpcinfo -p'), 'Use the actual system RPC binary for optional diagnostics');
foreach (['', 'command timed out', 'RPC: Remote system error - No route to host'] as $rpc_output) {
	[$registered, $text] = capture(fn() => getSupportedNFSVersions('192.0.2.10'));
	check(!$registered && str_contains($text, 'does not rule out NFSv4'), 'Missing RPC registrations must not declare NFSv4 unavailable');
}

echo "PASS: $checks regression checks\n";
