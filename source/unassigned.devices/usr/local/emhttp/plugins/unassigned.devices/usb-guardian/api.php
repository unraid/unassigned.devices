<?php
declare(strict_types=1);

require_once '/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/include/api_helpers.php';

$guardian_request_id = bin2hex(random_bytes(8));

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        throw new GuardianApiException('POST is required.', 405);
    }
    $contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($contentLength < 0 || $contentLength > 16384) {
        throw new GuardianApiException('Request body is too large.', 413);
    }

    // Unraid's PHP auto_prepend validates every POST, then removes the consumed
    // csrf_token field/header before dispatching to the plugin endpoint.

    $action = guardian_request_string('action', 4, 24, '/\A(?:list|eject|status|jobs|lease|settings|save_settings|clear_logs|diagnostics)\z/');
    guardian_ensure_runtime_dirs();
    guardian_require_not_maintaining();

    switch ($action) {
        case 'list':
            guardian_require_runtime();
            guardian_require_enabled();
            guardian_json_response(['ok' => true, 'data' => guardian_list_devices()]);

        case 'eject':
            guardian_require_runtime();
            guardian_require_enabled();
            $token = guardian_request_string('target', 16, 768, '/\A[A-Za-z0-9._~:+\/=\-]+\z/');
            $devices = guardian_list_devices();
            $device = guardian_find_device_by_token($devices, $token);
            if ($device === null) {
                guardian_api_log('eject_rejected_unknown_target', ['target_sha256' => hash('sha256', $token)]);
                throw new GuardianApiException('The device token is stale or invalid. Refresh the device list.', 409);
            }
            if (($device['eligible'] ?? false) !== true) {
                $reasons = is_array($device['reasons'] ?? null) ? $device['reasons'] : [];
                guardian_api_log('eject_rejected_ineligible', [
                    'target_sha256' => hash('sha256', $token),
                    'reason_codes' => array_values(array_filter(array_map(
                        static fn($reason) => is_array($reason) ? (string)($reason['code'] ?? '') : '',
                        $reasons
                    ))),
                ]);
                throw new GuardianApiException('This USB device is not eligible for safe eject.', 409, ['reasons' => $reasons]);
            }
            guardian_json_response(['ok' => true, 'data' => guardian_launch_eject($token, $device)], 202);

        case 'status':
            $jobId = guardian_request_string('job_id', 36, 36, '/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/');
            guardian_json_response(['ok' => true, 'data' => guardian_status($jobId)]);

        case 'jobs':
            guardian_json_response(['ok' => true, 'data' => guardian_recent_jobs()]);

        case 'lease':
            guardian_require_runtime();
            $jobId = guardian_request_string('job_id', 36, 36, '/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/');
            $generationValue = guardian_request_string('generation', 1, 19, '/\A[1-9][0-9]{0,18}\z/');
            $generation = filter_var($generationValue, FILTER_VALIDATE_INT, [
                'options' => ['min_range' => 1, 'max_range' => PHP_INT_MAX],
            ]);
            if ($generation === false) {
                throw new GuardianApiException('Invalid parameter: generation', 400);
            }
            guardian_json_response(['ok' => true, 'data' => guardian_lease($jobId, $generation)]);

        case 'settings':
            guardian_json_response(['ok' => true, 'data' => guardian_load_settings()]);

        case 'save_settings':
            $settings = guardian_validate_settings_request();
            guardian_save_settings_guarded($settings);
            guardian_api_log('settings_saved', ['settings' => $settings]);
            guardian_json_response(['ok' => true, 'data' => $settings]);

        case 'clear_logs':
            guardian_json_response(['ok' => true, 'data' => guardian_clear_logs()]);

        case 'diagnostics':
            if (!is_file(GUARDIAN_BINARY) || !is_executable(GUARDIAN_BINARY)) {
                throw new GuardianApiException('USB Guardian core binary is unavailable.', 503);
            }
            guardian_send_diagnostics();
    }

    throw new GuardianApiException('Unsupported action.', 400);
} catch (GuardianApiException $exception) {
    guardian_api_log('api_error', [
        'status' => $exception->httpStatus,
        'message' => $exception->getMessage(),
        'action' => is_string($_POST['action'] ?? null) ? $_POST['action'] : '',
    ]);
    guardian_json_response([
        'ok' => false,
        'error' => [
            'message' => $exception->getMessage(),
            'details' => $exception->details,
            'request_id' => $guardian_request_id,
        ],
    ], $exception->httpStatus);
} catch (Throwable $exception) {
    guardian_api_log('api_unhandled_error', [
        'type' => get_class($exception),
        'message' => $exception->getMessage(),
        'file' => $exception->getFile(),
        'line' => $exception->getLine(),
        'trace' => substr($exception->getTraceAsString(), 0, 8000),
        'action' => is_string($_POST['action'] ?? null) ? $_POST['action'] : '',
    ]);
    guardian_json_response([
        'ok' => false,
        'error' => [
            'message' => 'Unexpected USB Guardian API failure.',
            'request_id' => $guardian_request_id,
        ],
    ], 500);
}
