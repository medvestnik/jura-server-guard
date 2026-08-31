#!/usr/bin/env php
<?php
/**
 * Jura Server Guard - SSH authorized_keys monitor.
 *
 * Detects newly added SSH public keys in monitored authorized_keys files and
 * sends Telegram alerts. Designed to be called from cron/systemd every minute.
 */

declare(strict_types=1);

$basePath = dirname(__DIR__);
loadEnv($basePath . '/.env');

$options = parseOptions($argv);
$files = monitoredFiles($options);
$stateFile = $options['state'] ?? envValue('JURA_SSH_KEY_MONITOR_STATE', $basePath . '/storage/ssh-key-monitor/authorized_keys_state.json');
$notifyInitial = isset($options['notify-initial']);
$dryRun = isset($options['dry-run']);
$failOnNew = isset($options['fail-on-new']);

$current = [];
$errors = [];
foreach ($files as $file) {
    if (!is_file($file)) {
        continue;
    }
    if (!is_readable($file)) {
        $errors[] = "File is not readable: {$file}";
        continue;
    }
    foreach (readAuthorizedKeys($file) as $key) {
        $id = $file . '|' . $key['fingerprint'];
        $current[$id] = $key;
    }
}

$previous = readState($stateFile);
$previousKeys = $previous['keys'] ?? [];
$isFirstRun = empty($previousKeys) && !is_file($stateFile);

$new = [];
foreach ($current as $id => $key) {
    if (!isset($previousKeys[$id])) {
        $new[$id] = $key;
    }
}

$state = [
    'generated_at' => date(DATE_ATOM),
    'hostname' => gethostname() ?: php_uname('n'),
    'files' => array_values($files),
    'keys' => $current,
];

if (!$dryRun) {
    writeState($stateFile, $state);
}

if ($errors) {
    foreach ($errors as $error) {
        fwrite(STDERR, "WARNING: {$error}\n");
    }
}

if ($isFirstRun && !$notifyInitial) {
    echo "SSH key monitor baseline created. Keys seen: " . count($current) . "\n";
    echo "No alert was sent on first run. Use --notify-initial to notify about initial keys.\n";
    exit(0);
}

if (!$new) {
    echo "SSH key monitor complete. No new keys. Keys seen: " . count($current) . "\n";
    exit(0);
}

$notifierEnabled = boolEnv('JURA_TELEGRAM_ENABLED', false)
    && envValue('JURA_TELEGRAM_BOT_TOKEN', '') !== ''
    && envValue('JURA_TELEGRAM_CHAT_ID', '') !== '';

foreach ($new as $key) {
    $message = buildTelegramMessage($key, $isFirstRun);
    echo "NEW SSH KEY: {$key['file']} {$key['fingerprint']} {$key['comment']}\n";
    if ($notifierEnabled && !$dryRun) {
        $result = sendTelegram($message);
        if (!$result['ok']) {
            fwrite(STDERR, "Telegram failed: {$result['error']}\n");
        }
    } elseif (!$notifierEnabled) {
        fwrite(STDERR, "Telegram is disabled or not configured. Set JURA_TELEGRAM_ENABLED=true, JURA_TELEGRAM_BOT_TOKEN and JURA_TELEGRAM_CHAT_ID.\n");
    }
}

exit($failOnNew ? 2 : 0);

/** @return array<string,string> */
function parseOptions(array $argv): array
{
    $options = [];
    foreach (array_slice($argv, 1) as $arg) {
        if (str_starts_with($arg, '--') && str_contains($arg, '=')) {
            [$name, $value] = explode('=', substr($arg, 2), 2);
            $options[$name] = $value;
        } elseif (str_starts_with($arg, '--')) {
            $options[substr($arg, 2)] = '1';
        }
    }
    return $options;
}

/** @return string[] */
function monitoredFiles(array $options): array
{
    $raw = $options['files'] ?? envValue('JURA_SSH_KEY_MONITOR_FILES', '/root/.ssh/authorized_keys');
    $files = [];
    foreach (array_filter(array_map('trim', explode(',', $raw))) as $pattern) {
        $matches = glob($pattern, GLOB_NOSORT);
        if ($matches === false || $matches === []) {
            $files[] = $pattern;
            continue;
        }
        foreach ($matches as $match) {
            $files[] = $match;
        }
    }
    return array_values(array_unique($files));
}

/** @return array<int,array<string,string|int|null>> */
function readAuthorizedKeys(string $file): array
{
    $lines = file($file, FILE_IGNORE_NEW_LINES) ?: [];
    $keys = [];
    foreach ($lines as $lineNumber => $line) {
        $trimmed = trim($line);
        if ($trimmed === '' || str_starts_with($trimmed, '#')) {
            continue;
        }
        $parsed = parseAuthorizedKeyLine($trimmed);
        if ($parsed === null) {
            continue;
        }
        $fingerprint = fingerprintForLine($trimmed);
        if ($fingerprint === null) {
            $fingerprint = 'SHA256:' . hash('sha256', $parsed['type'] . ' ' . $parsed['key']);
        }
        $keys[] = [
            'file' => $file,
            'line' => $lineNumber + 1,
            'type' => $parsed['type'],
            'fingerprint' => $fingerprint,
            'comment' => $parsed['comment'],
            'key_prefix' => substr($parsed['key'], 0, 16),
            'file_mtime' => @filemtime($file) ?: null,
            'file_owner' => ownerName($file),
        ];
    }
    return $keys;
}

/** @return array{type:string,key:string,comment:string}|null */
function parseAuthorizedKeyLine(string $line): ?array
{
    $tokens = preg_split('/\s+/', $line) ?: [];
    $keyTypeIndex = null;
    foreach ($tokens as $index => $token) {
        if (preg_match('/^(ssh-rsa|ssh-ed25519|ecdsa-sha2-[^\s]+|sk-ssh-[^\s]+|sk-ecdsa-[^\s]+)$/', $token)) {
            $keyTypeIndex = $index;
            break;
        }
    }
    if ($keyTypeIndex === null || !isset($tokens[$keyTypeIndex + 1])) {
        return null;
    }
    $commentTokens = array_slice($tokens, $keyTypeIndex + 2);
    return [
        'type' => $tokens[$keyTypeIndex],
        'key' => $tokens[$keyTypeIndex + 1],
        'comment' => implode(' ', $commentTokens),
    ];
}

function fingerprintForLine(string $line): ?string
{
    $tmp = tempnam(sys_get_temp_dir(), 'jsg-key-');
    if ($tmp === false) {
        return null;
    }
    file_put_contents($tmp, $line . "\n");
    $cmd = 'ssh-keygen -lf ' . escapeshellarg($tmp) . ' -E sha256 2>/dev/null';
    $out = shell_exec($cmd);
    @unlink($tmp);
    if (!is_string($out) || trim($out) === '') {
        return null;
    }
    if (preg_match('/\b(SHA256:[^\s]+)/', $out, $m)) {
        return $m[1];
    }
    return null;
}

function ownerName(string $file): string
{
    $uid = @fileowner($file);
    if ($uid === false) {
        return 'unknown';
    }
    $info = function_exists('posix_getpwuid') ? @posix_getpwuid($uid) : false;
    return is_array($info) && isset($info['name']) ? (string) $info['name'] : (string) $uid;
}

/** @return array{keys?:array<string,mixed>} */
function readState(string $stateFile): array
{
    if (!is_file($stateFile)) {
        return [];
    }
    $json = file_get_contents($stateFile);
    $data = json_decode((string) $json, true);
    return is_array($data) ? $data : [];
}

function writeState(string $stateFile, array $state): void
{
    $dir = dirname($stateFile);
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }
    $tmp = $stateFile . '.tmp.' . getmypid();
    file_put_contents($tmp, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    chmod($tmp, 0600);
    rename($tmp, $stateFile);
}

function buildTelegramMessage(array $key, bool $isInitial): string
{
    $host = gethostname() ?: php_uname('n');
    $mtime = isset($key['file_mtime']) && $key['file_mtime'] ? date('Y-m-d H:i:s T', (int) $key['file_mtime']) : 'unknown';
    $title = $isInitial ? '🔑 SSH key monitor initial key' : '🚨 New SSH authorized key detected';
    return $title . "\n"
        . "Host: {$host}\n"
        . "File: {$key['file']}\n"
        . "Owner: {$key['file_owner']}\n"
        . "Line: {$key['line']}\n"
        . "Type: {$key['type']}\n"
        . "Fingerprint: {$key['fingerprint']}\n"
        . "Comment: " . ($key['comment'] !== '' ? $key['comment'] : '-') . "\n"
        . "File mtime: {$mtime}";
}

/** @return array{ok:bool,error?:string} */
function sendTelegram(string $message): array
{
    $token = envValue('JURA_TELEGRAM_BOT_TOKEN', '');
    $chatId = envValue('JURA_TELEGRAM_CHAT_ID', '');
    $url = "https://api.telegram.org/bot{$token}/sendMessage";
    $payload = http_build_query([
        'chat_id' => $chatId,
        'text' => $message,
        'disable_web_page_preview' => true,
    ]);

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
        ]);
        $response = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($errno) {
            return ['ok' => false, 'error' => "cURL error: {$error}"];
        }
        if ($httpCode !== 200) {
            return ['ok' => false, 'error' => "Telegram API returned HTTP {$httpCode}: " . substr((string) $response, 0, 500)];
        }
        return ['ok' => true];
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => $payload,
            'timeout' => 10,
        ],
    ]);
    $response = @file_get_contents($url, false, $context);
    if ($response === false) {
        return ['ok' => false, 'error' => 'file_get_contents failed'];
    }
    return ['ok' => true];
}

function loadEnv(string $file): void
{
    if (!is_file($file) || !is_readable($file)) {
        return;
    }
    foreach (file($file, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }
        [$name, $value] = explode('=', $line, 2);
        $name = trim($name);
        $value = trim($value);
        if ($value !== '' && (($value[0] === '"' && str_ends_with($value, '"')) || ($value[0] === "'" && str_ends_with($value, "'")))) {
            $value = substr($value, 1, -1);
        }
        if ($name !== '' && getenv($name) === false) {
            putenv($name . '=' . $value);
            $_ENV[$name] = $value;
        }
    }
}

function envValue(string $name, string $default = ''): string
{
    $value = getenv($name);
    return $value === false ? $default : (string) $value;
}

function boolEnv(string $name, bool $default = false): bool
{
    $value = getenv($name);
    if ($value === false || $value === '') {
        return $default;
    }
    return in_array(strtolower((string) $value), ['1', 'true', 'yes', 'on'], true);
}
