<?php
function base_path(string $path = ''): string { return dirname(__DIR__, 2) . ($path ? DIRECTORY_SEPARATOR . ltrim($path, '/') : ''); }
function storage_path(string $path = ''): string { return base_path('storage' . ($path ? DIRECTORY_SEPARATOR . ltrim($path, '/') : '')); }
function config_path(string $path = ''): string { return base_path('config' . ($path ? DIRECTORY_SEPARATOR . ltrim($path, '/') : '')); }
function env_value(string $key, mixed $default = null): mixed {
    static $env = null;
    if ($env === null) {
        $env = $_ENV;
        $file = base_path('.env');
        if (is_file($file)) {
            foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) continue;
                [$k, $v] = explode('=', $line, 2);
                $v = trim($v, " \t\n\r\0\x0B\"'");
                $env[trim($k)] = $v;
            }
        }
    }
    return $env[$key] ?? getenv($key) ?: $default;
}
function config(string $key, mixed $default = null): mixed {
    static $configs = [];
    [$file, $rest] = array_pad(explode('.', $key, 2), 2, null);
    if (!isset($configs[$file])) $configs[$file] = is_file(config_path("$file.php")) ? require config_path("$file.php") : [];
    $value = $configs[$file];
    foreach (explode('.', (string) $rest) as $part) {
        if ($part === '') continue;
        if (!is_array($value) || !array_key_exists($part, $value)) return $default;
        $value = $value[$part];
    }
    return $value;
}
function view(string $name, array $data = []): string {
    extract($data, EXTR_SKIP);
    ob_start();
    include base_path('resources/views/' . str_replace('.', '/', $name) . '.php');
    return ob_get_clean();
}
function e(mixed $value): string { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function redirect(string $to): never { header('Location: ' . $to); exit; }
function now(): string { return gmdate('Y-m-d H:i:s'); }
function bool_env(string $key, bool $default = false): bool { return filter_var(env_value($key, $default ? 'true' : 'false'), FILTER_VALIDATE_BOOLEAN); }

function scan_pid_alive(int $pid): bool { return $pid > 0 && (function_exists('posix_kill') ? @posix_kill($pid, 0) : is_dir('/proc/'.$pid)); }
function scan_heartbeat_age(?array $run): ?int {
    if (!$run || empty($run['last_heartbeat_at'])) return null;
    $ts = strtotime((string)$run['last_heartbeat_at']);
    return $ts ? max(0, time() - $ts) : null;
}
function scan_active_context(): array {
    $run = \App\Support\DB::first("SELECT * FROM scan_runs WHERE status = 'running' ORDER BY started_at DESC LIMIT 1");
    $lock = (new \App\Support\ScanLock())->read();
    $pid = (int)($run['pid'] ?? $lock['pid'] ?? 0);
    $pidAlive = $pid > 0 ? scan_pid_alive($pid) : false;
    $age = scan_heartbeat_age($run);
    $threshold = (int)config('guard.scan_stale_seconds', 60);
    $stale = (bool)$run && (($age !== null && $age > $threshold) || ($pid > 0 && !$pidAlive));
    $total = (int)($run['total_files_estimated'] ?? 0);
    $scanned = (int)($run['files_scanned'] ?? 0);
    $percent = $total > 0 ? min(100, (int)floor($scanned * 100 / $total)) : null;
    return ['exists'=>(bool)$run || (bool)$lock, 'run'=>$run, 'lock'=>$lock, 'pid_alive'=>$pidAlive, 'stale'=>$stale, 'heartbeat_age'=>$age, 'progress_percent'=>$percent];
}

function start_background_scan(string $scope, ?string $value, string $profile, int $maxSeconds = 0): void {
    $php = (string)env_value('JURA_PHP_BIN', PHP_BINARY);
    $cmd = [$php, base_path('artisan'), $scope === 'site' ? 'guard:scan-site' : ($scope === 'user' ? 'guard:scan-user' : 'guard:scan')];
    if ($scope !== 'full') $cmd[] = (string)$value;
    $cmd[] = '--profile='.$profile;
    if ($maxSeconds >= 0) $cmd[] = '--max-seconds='.$maxSeconds;
    $parts = array_map('escapeshellarg', $cmd);
    $out = storage_path('logs/web-scan.log');
    if (!is_dir(dirname($out))) mkdir(dirname($out), 0750, true);
    exec('nohup '.implode(' ', $parts).' >> '.escapeshellarg($out).' 2>&1 < /dev/null &');
}
function scan_buttons_disabled(): bool { return scan_active_context()['exists']; }
function flash(string $message): void { \App\Support\Auth::start(); $_SESSION['flash'] = $message; }
function redirect_back(string $fallback = '/'): never { redirect($_SERVER['HTTP_REFERER'] ?? $fallback); }
