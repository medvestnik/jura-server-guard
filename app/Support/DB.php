<?php
namespace App\Support;

use PDO;

class DB
{
    private static ?PDO $pdo = null;

    public static function driver(): string
    {
        $driver = strtolower((string) env_value('DB_CONNECTION', 'sqlite'));
        return in_array($driver, ['mysql', 'mariadb'], true) ? 'mysql' : 'sqlite';
    }

    public static function path(): string
    {
        $path = env_value('DB_DATABASE', storage_path('database.sqlite'));
        if ($path === ':memory:') return $path;
        if (!str_starts_with($path, '/')) $path = base_path($path);
        return $path;
    }

    public static function pdo(): PDO
    {
        if (!self::$pdo) {
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ];

            if (self::driver() === 'mysql') {
                $host = env_value('DB_HOST', '127.0.0.1');
                $port = env_value('DB_PORT', '3306');
                $db = env_value('DB_DATABASE', 'jura_server_guard');
                $charset = env_value('DB_CHARSET', 'utf8mb4');
                self::$pdo = new PDO("mysql:host={$host};port={$port};dbname={$db};charset={$charset}", env_value('DB_USERNAME', 'jsg'), env_value('DB_PASSWORD', ''), $options);
            } else {
                $path = self::path();
                if ($path !== ':memory:') {
                    if (!is_dir(dirname($path))) mkdir(dirname($path), 0750, true);
                    if (!file_exists($path)) touch($path);
                }
                self::$pdo = new PDO('sqlite:' . $path, null, null, $options);
                self::$pdo->exec('PRAGMA foreign_keys = ON');
                self::$pdo->exec('PRAGMA journal_mode = WAL');
                self::$pdo->exec('PRAGMA synchronous = NORMAL');
                self::$pdo->exec('PRAGMA busy_timeout = 5000');
            }
        }
        return self::$pdo;
    }

    public static function quoteIdentifier(string $identifier): string
    {
        return self::driver() === 'mysql' ? '`' . str_replace('`', '``', $identifier) . '`' : '"' . str_replace('"', '""', $identifier) . '"';
    }

    public static function boolExpr(bool $value): int { return $value ? 1 : 0; }
    public static function nowMinusHoursSql(int $hours): string { return self::driver() === 'mysql' ? "DATE_SUB(UTC_TIMESTAMP(), INTERVAL {$hours} HOUR)" : "datetime('now', '-{$hours} hours')"; }

    public static function select(string $sql, array $params = []): array { $st = self::pdo()->prepare($sql); $st->execute($params); return $st->fetchAll(); }
    public static function first(string $sql, array $params = []): ?array { return self::select($sql, $params)[0] ?? null; }
    public static function statement(string $sql, array $params = []): bool { $st = self::pdo()->prepare($sql); return $st->execute($params); }
    public static function insert(string $sql, array $params = []): int { self::statement($sql, $params); return (int) self::pdo()->lastInsertId(); }
}
