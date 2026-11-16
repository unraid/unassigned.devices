#!/usr/bin/php -q
<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require_once dirname(__DIR__).'/include/api_helpers.php';
try {
    guardian_ensure_runtime_dirs();
    if (($argv[1] ?? '') === 'prepare') {
        guardian_maintenance_prepare();
    } elseif (($argv[1] ?? '') === 'resume') {
        $lock = fopen(GUARDIAN_RUN_ROOT.'/api.lock', 'c+');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) throw new RuntimeException('Safe-eject API is busy.');
        try {
            if (file_exists(GUARDIAN_RUN_ROOT.'/maintenance') && !unlink(GUARDIAN_RUN_ROOT.'/maintenance')) {
                throw new RuntimeException('Unable to leave safe-eject maintenance mode.');
            }
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    } else {
        throw new RuntimeException('Usage: lifecycle.php prepare|resume');
    }
} catch (Throwable $error) {
    fwrite(STDERR, 'UD safe eject: '.$error->getMessage()."\n");
    exit(1);
}
