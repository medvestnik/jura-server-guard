#!/usr/bin/env php
<?php
/**
 * Jura Server Guard - suspicious process monitor.
 *
 * Detects suspicious running processes and sends Telegram alerts for newly observed
 * suspicious process signatures. Intended to be launched by systemd timer.
 */

declare(strict_types=1);

$basePath = dirname(__DIR__);
loadEnv($basePath . '/.env');
$options = parseOptions($argv);

$stateFile = $options['state'] ?? envValue('JURA_PROCESS_MONITOR_STATE', $basePath . '/storage/process-monitor/state.json');
$dryRun = isset($options['dry-run']);
$failOnNew = isset($options['fail-on-new']);
$includeInfo = isset($options['include-info']) || boolEnv('JURA_PROCESS_MONITOR_INCLUDE_INFO', false);
$ignoreRegex = envValue('JURA_PROCESS_MONITOR_IGNORE_REGEX', '');

$current = [];
foreach (scanProcesses($ignoreRegex, $includeInfo) as $hit) {
    $id = processSignature($hit);
    $current[$id] = $hit;
}

$previous = readState($stateFile);
$previousHits = $previous['hits'] ?? [];
$isFirstRun = empty($previousHits) && !is_file($stateFile);

$new = [];
foreach ($current as $id => $hit) {
    if (!isset($previousHits[$id])) {
        $new[$id] = $hit;
    }
}

$state = [
    'generated_at' => date(DATE_ATOM),
    'hostname' => gethostname() ?: php_uname('n'),
    'hits' => $current,
];

if (!$dryRun) {
    writeState($stateFile, $state);
}

if ($isFirstRun && !isset($options['notify-initial'])) {
    echo "Process monitor baseline created. Suspicious signatures seen: " . count($current) . "\n";
    echo "No alert was sent on first run. Use --notify-initial to notify about initial hits.\n";
    exit(0);
}

if (!$new) {
    echo "Process monitor complete. No new suspicious process signatures. Hits now: " . count($current) . "\n";
    exit(0);
}

$notifierEnabled = telegramEnabled();
foreach ($new as $hit) {
    echo "SUSPICIOUS PROCESS: pid={$hit['pid']} user={$hit['user']} severity={$hit['severity']} reason={$hit['reason_summary']}\n";
    if ($notifierEnabled && !$dryRun) {
        $result = sendTelegram(buildTelegramMessage($hit, $isFirstRun));
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

/** @return array<int,array<string,mixed>> */
function scanProcesses(string $ignoreRegex, bool $includeInfo): array
{
    $hits = [];
    foreach (scandir('/proc') ?: [] as $entry) {
        if (!ctype_digit($entry)) {
            continue;
        }
        $pid = (int) $entry;
        if ($pid <= 1 || $pid === getmypid()) {
            continue;
        }
        $proc = readProcess($pid);
        if ($proc === null) {
            continue;
        }
        $search = $proc['comm'] . "\n" . $proc['cmdline'] . "\n" . $proc['exe'] . "\n" . $proc['cwd'];
        if ($ignoreRegex !== '' && @preg_match($ignoreRegex, $search)) {
            continue;
        }
        $assessment = assessProcess($proc, $includeInfo);
        if ($assessment === null) {
            continue;
        }
        $proc['severity'] = $assessment['severity'];
        $proc['reasons'] = $assessment['reasons'];
        $proc['reason_summary'] = implode('; ', $assessment['reasons']);
        $hits[] = $proc;
    }
    usort($hits, fn(array $a, array $b) => [$b['severity_rank'], $a['pid']] <=> [$a['severity_rank'], $b['pid']]);
    return $hits;
}

/** @return array<string,mixed>|null */
function readProcess(int $pid): ?array
{
    $dir = "/proc/{$pid}";
    $status = @file_get_contents("{$dir}/status");
    if (!is_string($status)) {
        return null;
    }
    $name = '';
    $uid = null;
    foreach (explode("\n", $status) as $line) {
        if (str_starts_with($line, 'Name:')) {
            $name = trim(substr($line, 5));
        }
        if (str_starts_with($line, 'Uid:')) {
            $parts = preg_split('/\s+/', trim(substr($line, 4))) ?: [];
            $uid = isset($parts[0]) ? (int) $parts[0] : null;
        }
    }
    $cmdRaw = @file_get_contents("{$dir}/cmdline");
    $cmdline = is_string($cmdRaw) ? trim(str_replace("\0", ' ', $cmdRaw)) : '';
    $comm = trim((string) @file_get_contents("{$dir}/comm"));
    $exe = @readlink("{$dir}/exe");
    $cwd = @readlink("{$dir}/cwd");
    $user = $uid !== null ? userName($uid) : 'unknown';

    return [
        'pid' => $pid,
        'ppid' => processParentPid($status),
        'uid' => $uid,
        'user' => $user,
        'comm' => $comm !== '' ? $comm : $name,
        'cmdline' => $cmdline,
        'exe' => is_string($exe) ? $exe : '',
        'cwd' => is_string($cwd) ? $cwd : '',
    ];
}

function processParentPid(string $status): int
{
    foreach (explode("\n", $status) as $line) {
        if (str_starts_with($line, 'PPid:')) {
            return (int) trim(substr($line, 5));
        }
    }
    return 0;
}

/** @return array{severity:string,severity_rank:int,reasons:array<int,string>}|null */
function assessProcess(array $p, bool $includeInfo): ?array
{
    $reasons = [];
    $severity = 'medium';
    $text = strtolower($p['comm'] . ' ' . $p['cmdline'] . ' ' . $p['exe'] . ' ' . $p['cwd']);
    $exe = $p['exe'];
    $exeClean = str_replace(' (deleted)', '', $exe);
    $cmd = $p['cmdline'];
    $comm = strtolower($p['comm']);

    if ($exe !== '' && str_contains($exe, ' (deleted)')) {
        $reasons[] = 'process executable is deleted on disk';
        $severity = 'critical';
    }
    if ($exeClean !== '' && preg_match('#^/(tmp|var/tmp|dev/shm)(/|$)#', $exeClean)) {
        $reasons[] = 'executable runs from temporary memory/disk directory';
        $severity = maxSeverity($severity, 'critical');
    }
    if ($exeClean !== '' && preg_match('#^/var/www/[^/]+/data/(bin-tmp|mod-tmp|tmp)(/|$)#', $exeClean)) {
        $reasons[] = 'executable runs from hosting temporary directory';
        $severity = maxSeverity($severity, 'critical');
    }
    if ($exeClean !== '' && preg_match('#^/var/www/.+/data/www/.+/(tmp|cache|image|images|upload|uploads|files)/#', $exeClean)) {
        $reasons[] = 'executable runs from writable web directory';
        $severity = maxSeverity($severity, 'high');
    }

    $knownBadNames = ['gs-dbus', 'defunct-kernel', 'kdevtmpfsi', 'kinsing', 'xmrig', 'pnscan', 'zigw', 'dbused', 'watchbog'];
    foreach ($knownBadNames as $bad) {
        if ($comm === $bad || str_contains($text, $bad)) {
            $reasons[] = "known suspicious process marker: {$bad}";
            $severity = maxSeverity($severity, 'critical');
        }
    }

    if (preg_match('#(^|\s)(curl|wget)\s+[^|;]+\|\s*(sh|bash)\b#i', $cmd)) {
        $reasons[] = 'downloads and pipes remote script to shell';
        $severity = maxSeverity($severity, 'critical');
    }
    if (preg_match('#\b(base64\s+-d|openssl\s+enc|python\s+-c|perl\s+-e|php\s+-r)\b#i', $cmd) && preg_match('#\b(bash|sh|eval|exec)\b#i', $cmd)) {
        $reasons[] = 'inline encoded/eval shell execution pattern';
        $severity = maxSeverity($severity, 'high');
    }
    if (preg_match('#\b(paste\.myconan\.net|\.onion|masscan|zmap|/dev/tcp/)\b#i', $cmd)) {
        $reasons[] = 'known suspicious network/exfiltration marker in command line';
        $severity = maxSeverity($severity, 'high');
    }
    if (preg_match('#\b(php|perl|python|bash|sh)\b.*?/var/www/[^\s]+/data/(bin-tmp|mod-tmp|tmp)/#i', $cmd)) {
        $reasons[] = 'interpreter runs script from hosting temporary directory';
        $severity = maxSeverity($severity, 'critical');
    }
    if (preg_match('#\b(php|perl|python|bash|sh)\b.*?/var/www/[^\s]+/data/www/[^\s]+/(image|images|cache|tmp|upload|uploads|files)/#i', $cmd)) {
        $reasons[] = 'interpreter runs script from writable web directory';
        $severity = maxSeverity($severity, 'high');
    }

    if (!$reasons && $includeInfo && $p['user'] !== 'root' && preg_match('#\b(sshd|sftp-server|scp)\b#i', $cmd)) {
        $reasons[] = 'non-root SSH/SFTP child process observed';
        $severity = 'info';
    }

    if (!$reasons) {
        return null;
    }

    return ['severity' => $severity, 'severity_rank' => severityRank($severity), 'reasons' => array_values(array_unique($reasons))];
}

function maxSeverity(string $a, string $b): string
{
    return severityRank($b) > severityRank($a) ? $b : $a;
}

function severityRank(string $severity): int
{
    return match ($severity) {
        'critical' => 4,
        'high' => 3,
        'medium' => 2,
        'low' => 1,
        default => 0,
    };
}

function processSignature(array $hit): string
{
    $cmd = preg_replace('/\s+/', ' ', (string) $hit['cmdline']);
    $cmd = preg_replace('#/proc/\d+#', '/proc/N', (string) $cmd);
    $identity = implode('|', [$hit['user'], $hit['comm'], $hit['exe'], $hit['cwd'], $hit['reason_summary'], $cmd]);
    return hash('sha256', $identity);
}

function buildTelegramMessage(array $hit, bool $isInitial): string
{
    $host = gethostname() ?: php_uname('n');
    $title = $isInitial ? '⚙️ Process monitor initial suspicious process' : '🚨 Suspicious process detected';
    $cmd = $hit['cmdline'] !== '' ? $hit['cmdline'] : $hit['comm'];
    if (mb_strlen($cmd) > 900) {
        $cmd = mb_substr($cmd, 0, 900) . '…';
    }
    return $title . "\n"
        . "Host: {$host}\n"
        . "Severity: {$hit['severity']}\n"
        . "PID: {$hit['pid']} PPID: {$hit['ppid']}\n"
        . "User: {$hit['user']}\n"
        . "Command: {$cmd}\n"
        . "Exe: " . ($hit['exe'] !== '' ? $hit['exe'] : '-') . "\n"
        . "CWD: " . ($hit['cwd'] !== '' ? $hit['cwd'] : '-') . "\n"
        . "Reason: {$hit['reason_summary']}";
}

/** @return array{keys?:array<string,mixed>,hits?:array<string,mixed>} */
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

function userName(int $uid): string
{
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
