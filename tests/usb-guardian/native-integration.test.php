<?php
declare(strict_types=1);
$root = dirname(__DIR__, 2);
$ud = $root.'/source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices';
require_once $ud.'/include/SafeEject.php';
require_once $ud.'/usb-guardian/include/api_helpers.php';
$checks = 0;
function check(bool $ok, string $message): void {
    global $checks;
    if (!$ok) throw new RuntimeException($message);
    $checks++;
}
function blocked(callable $operation, string $message): void {
    try { $operation(); } catch (RuntimeException $error) { check(true, $message); return; }
    throw new RuntimeException($message);
}
$disk = ['id_bus'=>'usb', 'ud_device'=>true, 'device'=>'/dev/sdb', 'unassigned_dev'=>'Backup <&"', 'ud_dev'=>'dev1'];
$html = ud_safe_eject_control($disk, true);
check(str_contains($html, 'data-guardian-device="sdb"'), 'Render the authoritative disk identity.');
check(str_contains($html, 'Backup &lt;&amp;&quot;'), 'Escape disk names in attributes.');
check(!str_contains($html, 'onclick='), 'Bind controls without inline user data or JavaScript.');
foreach ([['array_disk'=>true], ['pool_disk'=>true], ['pass_through'=>true], ['id_bus'=>'ata'], ['device'=>'/dev/nvme0n1'], ['ud_device'=>false]] as $override) {
    check(ud_safe_eject_control(array_replace($disk, $override), true) === '', 'Exclude non-UD or unsupported targets.');
}
check(ud_safe_eject_control($disk, false) === '', 'Disabled controls must not render.');
$_SESSION['locale'] = 'zh_CN';
check(str_contains(ud_safe_eject_control($disk, true), '安全弹出'), 'Native PHP controls use the selected catalog.');

$_POST = ['ENABLED'=>'no','LOG_LEVEL'=>'info','LOG_RETENTION_DAYS'=>'30','MAX_LOG_MIB'=>'128','LOG_KEEP'=>'20','SETTLE_SECONDS'=>'30','SHFS_HEALTH_SECONDS'=>'5','ENABLE_SG_IO'=>'yes'];
check(guardian_validate_settings_request()['ENABLED'] === 'no', 'Validate native settings.');
$_POST['SETTLE_SECONDS']='0';
blocked(fn()=>guardian_validate_settings_request(), 'Do not accept disabling the safety window.');
$launch = (string)file_get_contents($ud.'/usb-guardian/include/api_helpers.php');
check(str_contains($launch, "try {\n        guardian_require_not_maintaining();"), 'Recheck maintenance after acquiring the launch lock.');
check(!str_contains($launch, '7.2.4') && !str_contains($launch, 'version_compare('), 'Remove deployment-version gates.');
$page = (string)file_get_contents($ud.'/UnassignedDevices.page');
check(str_contains($page, 'window.UDSafeEject?.refreshControls();'), 'Native table refresh updates controls explicitly.');
$plg = (string)file_get_contents($root.'/unassigned.devices.plg');
check(strpos($plg, '"$safe_eject_guard" prepare') < strpos($plg, 'Run="upgradepkg'), 'Enter maintenance before replacing the installed package.');
check(str_contains($plg, 'scripts/lifecycle.php prepare || exit 1'), 'Refuse removal on an active operation.');

$fixture = sys_get_temp_dir().'/ud-native-eject-'.bin2hex(random_bytes(6));
$run=$fixture.'/run'; $log=$fixture.'/logs';
mkdir($run.'/jobs',0700,true); mkdir($run.'/ud-adapter',0700,true); mkdir($log.'/transactions',0700,true);
try {
    $api=fopen($run.'/api.lock','c+'); flock($api,LOCK_EX);
    blocked(fn()=>guardian_maintenance_prepare($run,$log),'A concurrent launch must block maintenance.');
    flock($api,LOCK_UN); fclose($api);
    $transaction=fopen($log.'/.transaction.lock','c+'); flock($transaction,LOCK_EX);
    blocked(fn()=>guardian_maintenance_prepare($run,$log),'An active worker must block maintenance.');
    flock($transaction,LOCK_UN); fclose($transaction);
    foreach (['queued','running'] as $state) {
        file_put_contents($run.'/jobs/test.json',json_encode(['state'=>$state]));
        blocked(fn()=>guardian_maintenance_prepare($run,$log),'Queued and running jobs must block replacement.');
    }
    file_put_contents($run.'/jobs/test.json','malformed');
    blocked(fn()=>guardian_maintenance_prepare($run,$log),'Unreadable state must fail closed.');
    file_put_contents($run.'/jobs/test.json',json_encode(['state'=>'completed']));
    file_put_contents($run.'/ud-adapter/recovery.json','{}');
    blocked(fn()=>guardian_maintenance_prepare($run,$log),'Pending adapter recovery must block replacement.');
    unlink($run.'/ud-adapter/recovery.json');
    mkdir($log.'/transactions/test'); file_put_contents($log.'/transactions/test/active.json','{}');
    blocked(fn()=>guardian_maintenance_prepare($run,$log),'Persistent recovery evidence must block replacement.');
    unlink($log.'/transactions/test/active.json'); rmdir($log.'/transactions/test');
    check(!file_exists($run.'/maintenance'),'A refused update must leave the running UI enabled.');
    guardian_maintenance_prepare($run,$log);
    check(file_exists($run.'/maintenance'),'An idle update must block new launches across package replacement.');
} finally {
    $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($fixture,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach($iterator as $item) { $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname()); }
    rmdir($fixture);
}
echo "Native integration: $checks checks passed.\n";
