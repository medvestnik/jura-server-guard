<?php
namespace App\Support;

use PDO;

class DB
{
    private static ?PDO $pdo = null;

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
            $path = self::path();
            if ($path !== ':memory:') {
                if (!is_dir(dirname($path))) mkdir(dirname($path), 0750, true);
                if (!file_exists($path)) touch($path);
            }
            self::$pdo = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
            self::$pdo->exec('PRAGMA foreign_keys = ON');
        }
        return self::$pdo;
    }

    public static function select(string $sql, array $params = []): array { $st = self::pdo()->prepare($sql); $st->execute($params); return $st->fetchAll(); }
    public static function first(string $sql, array $params = []): ?array { return self::select($sql, $params)[0] ?? null; }
    public static function statement(string $sql, array $params = []): bool { $st = self::pdo()->prepare($sql); return $st->execute($params); }
    public static function insert(string $sql, array $params = []): int { self::statement($sql, $params); return (int) self::pdo()->lastInsertId(); }
}
