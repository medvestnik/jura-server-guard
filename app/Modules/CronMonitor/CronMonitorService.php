<?php
namespace App\Modules\CronMonitor;

use App\Support\DB;

class CronMonitorService
{
    /** @return array<int,array{id:int,server_user:string,line:string}> newly observed crontab lines */
    public function scan(): array
    {
        $new = [];
        foreach (DB::select('SELECT id, name FROM users ORDER BY name') as $user) {
            $new = array_merge($new, $this->scanUser((int) $user['id'], (string) $user['name']));
        }
        return $new;
    }

    private function scanUser(int $userId, string $serverUser): array
    {
        $lines = $this->readCrontab($serverUser);
        $seenHashes = [];
        $new = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) continue;
            $hash = hash('sha256', $line);
            $seenHashes[$hash] = true;
            $existing = DB::first('SELECT id FROM cron_snapshots WHERE server_user=? AND line_hash=?', [$serverUser, $hash]);
            if ($existing) {
                DB::statement('UPDATE cron_snapshots SET is_missing=0, last_seen_at=?, updated_at=? WHERE id=?', [now(), now(), $existing['id']]);
                continue;
            }
            $id = DB::insert('INSERT INTO cron_snapshots (user_id,server_user,line,line_hash,is_missing,first_seen_at,last_seen_at,created_at,updated_at) VALUES (?,?,?,?,0,?,?,?,?)', [$userId, $serverUser, $line, $hash, now(), now(), now(), now()]);
            $new[] = ['id' => $id, 'server_user' => $serverUser, 'line' => $line];
        }
        foreach (DB::select('SELECT id, line_hash FROM cron_snapshots WHERE server_user=? AND is_missing=0', [$serverUser]) as $row) {
            if (!isset($seenHashes[$row['line_hash']])) DB::statement('UPDATE cron_snapshots SET is_missing=1, updated_at=? WHERE id=?', [now(), $row['id']]);
        }
        return $new;
    }

    /** @return string[] raw crontab lines, or [] if the user has no crontab / it can't be read */
    private function readCrontab(string $serverUser): array
    {
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $proc = @proc_open(['crontab', '-l', '-u', $serverUser], $descriptors, $pipes);
        if (!is_resource($proc)) return [];
        $out = stream_get_contents($pipes[1]) ?: '';
        fclose($pipes[1]);
        if (isset($pipes[2])) fclose($pipes[2]);
        $code = proc_close($proc);
        if ($code !== 0) return [];
        return explode("\n", $out);
    }
}
