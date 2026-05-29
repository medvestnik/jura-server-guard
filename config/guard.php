<?php
return [
    'scan_roots' => array_values(array_filter(array_map('trim', explode(',', (string) env_value('JURA_SCAN_ROOTS', '/var/www'))))),
    'site_pattern' => env_value('JURA_SITE_PATTERN', '/var/www/*/data/www/*'),
    'log_paths' => [
        '/var/www/*/data/logs/*.access.log',
        '/var/www/*/data/logs/*.error.log',
        '/var/www/httpd-logs/*.access.log',
        '/var/www/httpd-logs/*.error.log',
        '/var/log/secure',
        '/var/log/auth.log',
    ],
    'quarantine_path' => env_value('JURA_QUARANTINE_PATH', '/root/jura-server-guard/quarantine'),
    'web_actions_enabled' => bool_env('JURA_WEB_ACTIONS_ENABLED', false),
    'scan_interval_minutes' => (int) env_value('JURA_SCAN_INTERVAL_MINUTES', 10),
    'max_file_read_bytes' => (int) env_value('JURA_MAX_FILE_READ_BYTES', 262144),
    'openai_enabled' => bool_env('JURA_OPENAI_ENABLED', false),
    'openai_api_key' => env_value('JURA_OPENAI_API_KEY', ''),
];
