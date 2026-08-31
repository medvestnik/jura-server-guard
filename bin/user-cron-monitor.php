#!/usr/bin/env php
<?php
/**
 * Jura Server Guard - user/system cron monitor.
 *
 * Detects newly added or changed user crontabs and system cron files and sends
 * Telegram alerts. Intended to be launched by systemd timer.
 */

declare(strict_types=1);

$basePath = dirname(__DIR__);
loadEnv($basePath . '/.env');
$options = parseOptions($argv);

$files = monitoredCronFiles($options);
$stateFile = $options['state'] ?? envValue('JURA_USER_CRON_MONITOR_STATE', $basePath . '/storage/user-cron-monitor/state.json');
$dryRun = isset($options['dry-run']);
$failOnNew = isset($options['fail-on-new']);
$notifyInitial = isset($options['notify-initial']);

$currentFiles = [];
$currentLines = [];
$events = [];

foreach ($files as $file) {
    if (!is_file($file) || !is_readable($file)) {
        continue;
    }
    $content = (string) file_get_contents($file);
    $fileInfo = cronFileInfo($file, $content);
    $currentFiles[$file] = $fileInfo;
    foreach (cronInterestingLines($file, $content) as $lineInfo) {
        $lineId = $file . '|' . $lineInfo['line_hash'];
        $currentLines[$lineId] = $lineInfo;
    }
}

$previous = readState($stateFile);
$previousFiles = $previous['files'] ?? [];
$previousLines = $previous['lines'] ?? [];
$isFirstRun = empty($previousFiles) && !is_file($stateFile);

foreach ($currentFiles as $path => $info) {
    if (!isset($previousFiles[$path])) {
        $events[] = ['kind' => 'new_cron_file'] + $info;
        continue;
    }
    if (($previousFiles[$path]['sha256'] ?? '') !== $info['sha256']) {
        $events[] = ['kind' => 'changed_cron_file'] + $info;
    }
}

foreach ($currentLines as $id => $lineInfo) {
    if (!isset($previousLines[$id])) {
        $events[] = ['kind' => 'new_cron_line'] + $lineInfo;
    }
}

$state = [
    'generated_at' => date(DATE_ATOM),
    'hostname' => gethostname() ?: php_uname('n'),
    'files' => $currentFiles,
    'lines' => $currentLines,
];

if (!$dryRun) {
    writeState($stateFile, $state);
}

if ($isFirstRun && !$notifyInitial) {
    echo "Cron monitor baseline created. Files: " . count($currentFiles) . ", lines: " . count($currentLines) . "\n";
    echo "No alert was sent on first run. Use --notify-initial to notify about initial cron entries.\n";
    exit(0);
}

if (!$events) {
    echo "Cron monitor complete. No new cron changes. Files: " . count($currentFiles) . ", lines: " . count($currentLines) . "\n";
    exit(0);
}

$notifierEnabled = telegramEnabled();
foreach ($events as $event) {
    echo "CRON CHANGE: {$event['kind']} {$event['file']}\n";
    if ($notifierEnabled && !$dryRun) {
        $result = sendTelegram(buildTelegramMessage($event, $isFirstRun));
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
function monitoredCronFiles(array $options): array
{
    $default = '/var/spool/cron/*,/var/spool/cron/crontabs/*,/etc/crontab,/etc/cron.d/*,/etc/cron.hourly/*,/etc/cron.daily/*,/etc/cron.weekly/*,/etc/cron.monthly/*';
    $raw = $options['files'] ?? envValue('JURA_USER_CRON_MONITOR_FILES', $default);
    $files = [];
    foreach (array_filter(array_map('trim', explode(',', $raw))) as $pattern) {
        $matches = glob($pattern, GLOB_NOSORT);
        if ($matches === false || $matches === []) {
            continue;
        }
        foreach ($matches as $match) {
            if (is_file($match)) {
                $files[] = $match;
            }
        }
    }
    sort($files);
    return array_values(array_unique($files));
}

/** @return array<string,mixed> */
function cronFileInfo(string $file, string $content): array
{
    return [
        'file' => $file,
        'sha256' => hash('sha256', $content),
        'size' => strlen($content),
        'mtime' => @filemtime($file) ?: null,
        'owner' => ownerName($file),
        'mode' => sprintf('%04o', @fileperms($file) ? (@fileperms($file) & 07777) : 0),
    ];
}

/** @return array<int,array<string,mixed>> */
function cronInterestingLines(string $file, string $content): array
{
    $lines = [];
    foreach (explode("\n", $content) as $index => $line) {
        $trimmed = trim($line);
        if ($trimmed === '' || str_starts_with($trimmed, '#')) {
            continue;
        }
        if (preg_match('/^(SHELL|PATH|MAILTO|HOME|LOGNAME|USER)=/i', $trimmed)) {
            continue;
        }
        $lines[] = [
            'file' => $file,
            'line_no' => $index + 1,
            'line' => $trimmed,
            'line_hash' => hash('sha256', $trimmed),
            'owner' => ownerName($file),
            'mtime' => @filemtime($file) ?: null,
        ];
    }
    return $lines;
}

function buildTelegramMessage(array $event, bool $isInitial): string
{
    $host = gethostname() ?: php_uname('n');
    $titles = [
        'new_cron_file' => $isInitial ? '🕓 Cron monitor initial file' : '🚨 New cron file detected',
        'changed_cron_file' => '🚨 Cron file changed',
        'new_cron_line' => $isInitial ? '🕓 Cron monitor initial entry' : '🚨 New cron entry detected',
    ];
    $title = $titles[$event['kind']] ?? '🚨 Cron change detected';
    $mtime = isset($event['mtime']) && $event['mtime'] ? date('Y-m-d H:i:s T', (int) $event['mtime']) : 'unknown';
    $message = $title . "\n"
        . "Host: {$host}\n"
        . "File: {$event['file']}\n"
        . "Owner: " . ($event['owner'] ?? '-') . "\n"
        . "File mtime: {$mtime}";
    if (($event['kind'] ?? '') === 'new_cron_line') {
        $line = (string) ($event['line'] ?? '');
        if (mb_strlen($line) > 900) {
            $line = mb_substr($line, 0, 900) . '…';
        }
        $message .= "\nLine: " . ($event['line_no'] ?? '?') . "\nCommand: {$line}";
    } else {
        $message .= "\nSHA256: " . ($event['sha256'] ?? '-') . "\nMode: " . ($event['mode'] ?? '-');
    }
    return $message;
}

/** @return array{files?:array<string,mixed>,lines?:array<string,mixed>} */
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

function ownerName(string $file): string
{
    $uid = @fileowner($file);
    if ($uid === false) {
        return 'unknown';
    }
    $info = function_exists('posix_getpwuid') ? @posix_getpwuid($uid) : false;
    return is_array($info) && isset($info['name']) ? (string) $info['name'] : (string) $uid;
}

function telegramEnabled(): bool
{
    return boolEnv('JURA_TELEGRAM_ENABLED', false)
        && envValue('JURA_TELEGRAM_BOT_TOKEN', '') !== ''
        && envValue('JURA_TELEGRAM_CHAT_ID', '') !== '';
}

/** @return array{ok:bool,error?:string} */
function sendTelegram(string $message): array
{
    $token = envValue('JURA_TELEGRAM_BOT_TOKEN', '');
    $chatId = envValue('JURA_TELEGRAM_CHAT_ID', '');
    $url = "https://api.telegram.org/bot{$token}/sendMessage";
    $payload = http_build_query(['chat_id' => $chatId, 'text' => $message, 'disable_web_page_preview' => true]);
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $payload, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_CONNECTTIMEOUT => 5]);
        $response = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($errno) return ['ok' => false, 'error' => "cURL error: {$error}"];
        if ($httpCode !== 200) return ['ok' => false, 'error' => "Telegram API returned HTTP {$httpCode}: " . substr((string) $response, 0, 500)];
        return ['ok' => true];
    }
    $context = stream_context_create(['http' => ['method' => 'POST', 'header' => "Content-Type: application/x-www-form-urlencoded\r\n", 'content' => $payload, 'timeout' => 10]]);
    $response = @file_get_contents($url, false, $context);
    return $response === false ? ['ok' => false, 'error' => 'file_get_contents failed'] : ['ok' => true];
}

function loadEnv(string $file): void
{
    if (!is_file($file) || !is_readable($file)) return;
    foreach (file($file, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) continue;
        [$name, $value] = explode('=', $line, 2);
        $name = trim($name);
        $value = trim($value);
        if ($value !== '' && (($value[0] === '"' && str_ends_with($value, '"')) || ($value[0] === "'" && str_ends_with($value, "'")))) $value = substr($value, 1, -1);
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
    if ($value === false || $value === '') return $default;
    return in_array(strtolower((string) $value), ['1', 'true', 'yes', 'on'], true);
}
