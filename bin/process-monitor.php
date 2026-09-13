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
        $proc['severity_rank'] = $assessment['severity_rank'];
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
        $upgradeReason = describePackageUpgradeArtifact($exeClean, $cmd, (int) $p['pid']);
        if ($upgradeReason !== null) {
            $reasons[] = $upgradeReason;
            $severity = 'low';
        } else {
            $reasons[] = 'process executable is deleted on disk';
            $severity = 'critical';
        }
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

/**
 * A long-lived daemon (containerd-shim-runc-v2, containerd, dockerd, mariadbd, nginx, sshd, ...)
 * routinely keeps running from an unlinked (deleted) inode of its own binary right after
 * `dnf/yum update` replaces the file on disk: rpm/dnf unlink the old file and put the new one in
 * its place, and a process that already had the old file open keeps that inode alive -- it shows
 * as "(deleted)" until the process itself restarts. That's routine package-manager housekeeping,
 * not process-hollowing malware -- but only when BOTH of these hold, checked against the live RPM
 * database rather than a fixed binary allowlist or by parsing `dnf history`/`/var/log/dnf.log`
 * (fragile: locale/version-dependent formatting, log rotation loses old entries):
 *   (a) the currently-installed package owning this exact path was installed/upgraded (its RPM
 *       INSTALLTIME) AFTER this specific process started -- i.e. this process predates the
 *       upgrade that replaced its own (now-unlinked) binary;
 *   (b) for containerd-shim-runc-v2 specifically, the cmdline actually looks like a real
 *       containerd-launched shim invocation, not merely a process that happens to share the path.
 * Returns null (keep the original critical "deleted" alert) whenever either can't be confirmed --
 * unowned path, package not upgraded since the process started, RPM unavailable (this check is a
 * no-op on non-RPM systems), or start/update time unreadable. This only downgrades severity and
 * adds an explanatory reason; it never fully suppresses the finding, so the process stays visible
 * for a human to confirm and, if genuinely unrestarted since the upgrade, restart the service for.
 */
function describePackageUpgradeArtifact(string $exeClean, string $cmdline, int $pid): ?string
{
    if ($exeClean === '') {
        return null;
    }
    if (basename($exeClean) === 'containerd-shim-runc-v2' && !looksLikeContainerdShimInvocation($cmdline)) {
        return null;
    }
    $packageUpdatedAt = packageOwnerUpdateTime($exeClean);
    if ($packageUpdatedAt === null) {
        return null;
    }
    $startedAt = processStartTime($pid);
    if ($startedAt === null || $packageUpdatedAt < $startedAt) {
        return null;
    }
    return sprintf(
        'executable replaced by a package manager update on %s (process predates the update; restart the service/container to apply it)',
        date('Y-m-d H:i', $packageUpdatedAt)
    );
}

function looksLikeContainerdShimInvocation(string $cmdline): bool
{
    return (bool) preg_match('#-namespace\s+\S+#', $cmdline)
        && (bool) preg_match('#-id\s+[0-9a-f]{20,}\b#', $cmdline)
        && (bool) preg_match('#-address\s+/(run|var/run)/\S*containerd\.sock\b#', $cmdline);
}

/** Epoch seconds the package currently owning $path was installed/last upgraded, via the live RPM
 *  database (`rpm -q --qf '%{INSTALLTIME}' -f <path>`), or null when unowned, unreadable, or on a
 *  non-RPM system (rpm missing) -- callers must treat null as "can't confirm" and fail closed. */
function packageOwnerUpdateTime(string $path): ?int
{
    if (!function_exists('shell_exec')) {
        return null;
    }
    $out = @shell_exec('rpm -q --qf ' . escapeshellarg("%{INSTALLTIME}\n") . ' -f ' . escapeshellarg($path) . ' 2>/dev/null');
    if (!is_string($out)) {
        return null;
    }
    $latest = null;
    foreach (explode("\n", trim($out)) as $line) {
        $line = trim($line);
        if (ctype_digit($line)) {
            $ts = (int) $line;
            $latest = $latest === null ? $ts : max($latest, $ts);
        }
    }
    return $latest;
}

/** Epoch seconds a process started, derived from /proc/[pid]/stat field 22 (starttime, in clock
 *  ticks since boot) plus /proc/stat's btime. Parses past the process name field by finding the
 *  last ")" in the line, since a process name can itself contain spaces or parentheses. */
function processStartTime(int $pid): ?int
{
    $stat = @file_get_contents("/proc/{$pid}/stat");
    if (!is_string($stat)) {
        return null;
    }
    $rparen = strrpos($stat, ')');
    if ($rparen === false) {
        return null;
    }
    $fields = preg_split('/\s+/', trim(substr($stat, $rparen + 1))) ?: [];
    // Fields after ")" start at "state" (field 3 overall); starttime is field 22 overall, index 19 here.
    if (!isset($fields[19]) || !ctype_digit($fields[19])) {
        return null;
    }
    $boot = systemBootTime();
    $hz = clockTicksPerSecond();
    if ($boot === null || $hz <= 0) {
        return null;
    }
    return $boot + intdiv((int) $fields[19], $hz);
}

function systemBootTime(): ?int
{
    $stat = @file_get_contents('/proc/stat');
    if (!is_string($stat)) {
        return null;
    }
    foreach (explode("\n", $stat) as $line) {
        if (str_starts_with($line, 'btime ')) {
            return (int) trim(substr($line, 6));
        }
    }
    return null;
}

function clockTicksPerSecond(): int
{
    static $hz = null;
    if ($hz !== null) {
        return $hz;
    }
    $out = function_exists('shell_exec') ? trim((string) @shell_exec('getconf CLK_TCK 2>/dev/null')) : '';
    return $hz = (ctype_digit($out) && (int) $out > 0) ? (int) $out : 100;
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
    if (strlen($cmd) > 900) {
        $cmd = substr($cmd, 0, 900) . '…';
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
