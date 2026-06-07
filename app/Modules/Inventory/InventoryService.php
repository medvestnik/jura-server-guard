<?php
namespace App\Modules\Inventory;

use App\Support\DB;

class InventoryService
{
    public function refresh(?string $userFilter = null, ?string $sitePath = null, array $options = []): array
    {
        $paths = $sitePath ? [$sitePath] : (glob(config('guard.site_pattern'), GLOB_ONLYDIR) ?: []);
        $sites = [];
        foreach ($paths as $path) {
            $path = rtrim(realpath($path) ?: $path, '/');
            if (!is_dir($path)) continue;
            $type = $this->classify($path);
            if (!$this->shouldIncludeSite($path, $type, $options)) continue;
            $parts = explode('/', trim($path, '/'));
            $user = $parts[2] ?? basename(dirname(dirname($path)));
            if ($userFilter && $user !== $userFilter) continue;
            $base = "/var/www/$user";
            $userId = $this->upsertUser($user, $base);
            $sites[] = $this->upsertSite($userId, basename($path), $path, $type);
        }
        return $sites;
    }
    private function shouldIncludeSite(string $path, string $type, array $options): bool
    {
        $name = basename($path);
        $includeOld = (bool)($options['include_old'] ?? config('guard.scan_old_dubl_by_default'));
        $includeStorage = (bool)($options['include_storage'] ?? config('guard.scan_storage_by_default'));
        $includeBackups = (bool)($options['include_backups'] ?? false);

        if (in_array($type, ['old', 'dubl'], true) && !$includeOld) return false;
        if ($type === 'storage' && !$includeStorage) return false;
        if ($type === 'backup' && !$includeBackups) return false;

        foreach (config('guard.exclude_site_names') as $pattern) {
            if (fnmatch($pattern, $name, FNM_CASEFOLD) && !$includeOld && !$includeBackups) return false;
        }

        return true;
    }

    private function upsertUser(string $name, string $base): int
    {
        $row = DB::first('SELECT id FROM users WHERE name = ?', [$name]);
        if ($row) { DB::statement('UPDATE users SET base_path=?, updated_at=? WHERE id=?', [$base, now(), $row['id']]); return (int)$row['id']; }
        return DB::insert('INSERT INTO users (name, base_path, created_at, updated_at) VALUES (?,?,?,?)', [$name, $base, now(), now()]);
    }
    private function upsertSite(int $userId, string $name, string $path, string $type): array
    {
        $cms = $this->detectCms($path);
        $row = DB::first('SELECT id FROM sites WHERE path = ?', [$path]);
        if ($row) { DB::statement('UPDATE sites SET server_user_id=?, name=?, type=?, cms_type=?, is_active=1, updated_at=? WHERE id=?', [$userId,$name,$type,$cms,now(),$row['id']]); return DB::first('SELECT * FROM sites WHERE id=?', [$row['id']]); }
        $id = DB::insert('INSERT INTO sites (server_user_id,name,path,type,cms_type,is_active,created_at,updated_at) VALUES (?,?,?,?,?,1,?,?)', [$userId,$name,$path,$type,$cms,now(),now()]);
        return DB::first('SELECT * FROM sites WHERE id=?', [$id]);
    }
    public function classify(string $path): string
    {
        $n = strtolower(basename($path));
        return match (true) {
            str_contains($n, 'dubl') || str_contains($n, 'дубл') => 'dubl', str_contains($n, 'backup') || str_contains($n, 'bak') => 'backup', str_starts_with($n, 'old.') || str_contains($n, 'old') => 'old', str_contains($n, 'dev') || str_contains($n, 'test') => 'dev', str_contains($n, 'storage') => 'storage', preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/i', $n) => str_count($n, '.') > 1 ? 'subdomain' : 'domain', preg_match('/[^a-z0-9._-]/i', $n) || strlen($n) > 40 => 'suspicious', default => 'unknown'
        };
    }
    private function detectCms(string $path): ?string
    {
        if (is_file($path.'/wp-config.php')) return 'WordPress';
        if (is_file($path.'/configuration.php')) return 'Joomla';
        if (is_file($path.'/config.php') && is_file($path.'/admin/config.php')) return 'OpenCart';
        return null;
    }
}
