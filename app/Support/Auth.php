<?php
namespace App\Support;

class Auth
{
    public static function start(): void { if (session_status() !== PHP_SESSION_ACTIVE) session_start(); }
    public static function check(): bool { self::start(); return !empty($_SESSION['admin_id']); }
    public static function user(): ?array { self::start(); return $_SESSION['admin'] ?? null; }
    public static function attempt(string $email, string $password): bool {
        $user = DB::first('SELECT * FROM admin_users WHERE email = ?', [$email]);
        if ($user && password_verify($password, $user['password_hash'])) {
            self::start(); $_SESSION['admin_id'] = $user['id']; $_SESSION['admin'] = ['email' => $user['email']]; return true;
        }
        return false;
    }
    public static function logout(): void { self::start(); session_destroy(); }
    public static function require(): void { if (!self::check()) redirect('/login'); }
}
