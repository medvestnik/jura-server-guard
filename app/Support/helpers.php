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
function available_locales(): array { return ['ru' => 'Русский', 'uk' => 'Українська', 'en' => 'English']; }
function current_locale(): string {
    static $locale = null;
    if ($locale !== null) return $locale;
    $available = array_keys(available_locales());
    $cookie = $_COOKIE['jura_lang'] ?? null;
    if (is_string($cookie) && in_array($cookie, $available, true)) return $locale = $cookie;
    $default = (string) env_value('JURA_DEFAULT_LOCALE', 'ru');
    return $locale = in_array($default, $available, true) ? $default : 'en';
}
function translations(string $locale): array {
    static $tables = [];
    if (!isset($tables[$locale])) {
        $file = base_path("resources/lang/$locale.php");
        $tables[$locale] = ($locale !== 'en' && is_file($file)) ? require $file : [];
    }
    return $tables[$locale];
}
function t(string $text, array $replace = []): string {
    $translated = translations(current_locale())[$text] ?? $text;
    foreach ($replace as $key => $value) $translated = str_replace(':' . $key, (string) $value, $translated);
    return $translated;
}
/**
 * Validates a single IP address or CIDR range ("203.0.113.5" or "203.0.113.0/24"), refusing
 * private/loopback/link-local/reserved base addresses and -- for a range -- anything broader
 * than guard.firewall_min_cidr_prefix_v4/v6, so a single block action can't take out a huge
 * swath of address space by mistake. Returns null if invalid, otherwise the normalized pieces.
 *
 * @return array{ip:string,prefix:?int,version:int,cidr:string}|null
 */
function parse_ip_or_cidr(string $value): ?array
{
    $value = trim($value);
    if ($value === '') return null;
    $prefix = null;
    if (str_contains($value, '/')) {
        [$ip, $prefixStr] = explode('/', $value, 2);
        if (!preg_match('/^\d{1,3}$/', $prefixStr)) return null;
        $prefix = (int) $prefixStr;
    } else {
        $ip = $value;
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return null;
    $isV6 = (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    if ($prefix !== null && ($prefix < 0 || $prefix > ($isV6 ? 128 : 32))) return null;
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return null;
    $minPrefix = (int) config($isV6 ? 'guard.firewall_min_cidr_prefix_v6' : 'guard.firewall_min_cidr_prefix_v4');
    if ($prefix !== null && $prefix < $minPrefix) return null;
    return ['ip' => $ip, 'prefix' => $prefix, 'version' => $isV6 ? 6 : 4, 'cidr' => $prefix !== null ? "$ip/$prefix" : $ip];
}
/** True if $ip (a bare address) falls inside $cidr ("203.0.113.5" or "203.0.113.0/24" -- a bare
 *  address on the right is treated as a /32 or /128). Used to stop a CIDR block from silently
 *  swallowing an address already on the trusted list -- deliberately does not apply
 *  parse_ip_or_cidr()'s private/reserved-range or minimum-prefix rules, since a trusted entry is
 *  just being tested for geometric containment here, not validated as a new block target. */
function ip_in_cidr(string $ip, string $cidr): bool
{
    $ip = trim($ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
    $isV6 = (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    $cidr = trim($cidr);
    $prefix = $isV6 ? 128 : 32;
    if (str_contains($cidr, '/')) {
        [$netIp, $prefixStr] = explode('/', $cidr, 2);
        if (!preg_match('/^\d{1,3}$/', $prefixStr)) return false;
        $prefix = (int) $prefixStr;
    } else {
        $netIp = $cidr;
    }
    if (!filter_var($netIp, FILTER_VALIDATE_IP)) return false;
    if ($isV6 !== (bool) filter_var($netIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return false;
    if ($prefix < 0 || $prefix > ($isV6 ? 128 : 32)) return false;
    $ipBin = inet_pton($ip); $netBin = inet_pton($netIp);
    if ($ipBin === false || $netBin === false) return false;
    $bytes = intdiv($prefix, 8); $remainder = $prefix % 8;
    if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($netBin, 0, $bytes)) return false;
    if ($remainder === 0) return true;
    $mask = chr((0xFF << (8 - $remainder)) & 0xFF);
    return (substr($ipBin, $bytes, 1) & $mask) === (substr($netBin, $bytes, 1) & $mask);
}
