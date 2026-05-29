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
