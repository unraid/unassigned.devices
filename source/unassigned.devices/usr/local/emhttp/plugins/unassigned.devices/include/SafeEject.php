<?php
/* Native UD integration. USB Guardian core: Copyright (c) 2026 xO-ox-ai, MIT. */
require_once __DIR__.'/../usb-guardian/include/localization.php';

function ud_safe_eject_enabled(): bool {
    if (is_dir('/usr/local/emhttp/plugins/usb.guardian')) return false;
    $root = dirname(__DIR__).'/usb-guardian';
    if (!is_executable($root.'/bin/usb-guardian')) return false;
    $config = '/boot/config/plugins/unassigned.devices/usb-guardian/usb.guardian.cfg';
    $settings = @parse_ini_file(is_file($config) ? $config : $root.'/default.cfg', false, INI_SCANNER_RAW);
    return is_array($settings) && ($settings['ENABLED'] ?? 'yes') === 'yes';
}

function ud_safe_eject_control(array $disk, bool $enabled): string {
    if (!$enabled || ($disk['id_bus'] ?? '') !== 'usb' || empty($disk['ud_device'])
        || !empty($disk['array_disk']) || !empty($disk['pool_disk']) || !empty($disk['pass_through'])) return '';
    $device = basename((string)($disk['device'] ?? ''));
    if (!preg_match('/\Asd[a-z]+\z/D', $device)) return '';
    $name = (string)(($disk['unassigned_dev'] ?? '') ?: ($disk['ud_dev'] ?? $device));
    $escape = static function ($value) { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); };
    $label = usb_guardian_t('Safely eject {name}');
    $label = str_replace('{name}', $name, $label);
    // This control is an invitation to inspect, never an assertion of eligibility.
    return '<span class="usb-guardian-control-wrap"><button type="button" class="usb-guardian-control"'
        .' data-guardian-device="'.$escape($device).'" data-guardian-name="'.$escape($name).'"'
        .' title="'.$escape($label).'" aria-label="'.$escape($label).'">'
        .'<i class="fa fa-eject" aria-hidden="true"></i></button>'
        .'<span class="usb-guardian-control-status" role="status"></span></span>';
}
