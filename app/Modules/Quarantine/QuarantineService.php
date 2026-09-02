<?php
namespace App\Modules\Quarantine;

use App\Support\DB;
use RuntimeException;

class QuarantineService
{
    public function quarantine(int $findingId, string $reason = 'CLI quarantine'): int
    {
        $finding = DB::first('SELECT * FROM findings WHERE id=?', [$findingId]);
        if (!$finding) throw new RuntimeException('Finding not found.');
        $src = $finding['path']; if (!is_file($src)) throw new RuntimeException('Original file does not exist.');
        $dest = rtrim(config('guard.quarantine_path'), '/') . '/' . ltrim($src, '/');
        if (!is_dir(dirname($dest))) mkdir(dirname($dest), 0700, true);
        $stat = @stat($src) ?: []; $sha = hash_file('sha256', $src); $perms = substr(sprintf('%o', fileperms($src)), -4);
        $owner = function_exists('posix_getpwuid') ? (posix_getpwuid($stat['uid'] ?? 0)['name'] ?? (string)($stat['uid'] ?? '')) : null;
        $group = function_exists('posix_getgrgid') ? (posix_getgrgid($stat['gid'] ?? 0)['name'] ?? (string)($stat['gid'] ?? '')) : null;
        if (!rename($src, $dest)) throw new RuntimeException('Failed to move file to quarantine.');
        $groupCol = DB::quoteIdentifier('group');
        $originalPathHash = hash('sha256', $src);
        $id = DB::insert("INSERT INTO quarantine_items (finding_id,original_path,original_path_hash,quarantine_path,sha256,owner,$groupCol,permissions,mtime,reason,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [$findingId,$src,$originalPathHash,$dest,$sha,$owner,$group,$perms,isset($stat['mtime'])?gmdate('Y-m-d H:i:s',$stat['mtime']):null,$reason,'quarantined',now(),now()]);
        DB::statement('UPDATE findings SET status=?, updated_at=? WHERE id=?', ['quarantined', now(), $findingId]);
        return $id;
    }
    public function delete(int $findingId, string $reason = 'CLI delete'): int
    {
        $finding = DB::first('SELECT * FROM findings WHERE id=?', [$findingId]);
        if (!$finding) throw new RuntimeException('Finding not found.');
        if (($finding['status'] ?? '') === 'deleted') return 0;
        if (($finding['status'] ?? '') === 'quarantined') {
            $item = DB::first("SELECT * FROM quarantine_items WHERE finding_id=? AND status='quarantined' ORDER BY id DESC LIMIT 1", [$findingId]);
            if (!$item) throw new RuntimeException('Quarantine item not found.');
            if (is_file($item['quarantine_path']) && !@unlink($item['quarantine_path'])) throw new RuntimeException('Failed to permanently delete quarantined file.');
            DB::statement('UPDATE quarantine_items SET status=?, reason=?, updated_at=? WHERE id=?', ['deleted', $reason, now(), $item['id']]);
            DB::statement('UPDATE findings SET status=?, updated_at=? WHERE path=? AND status<>?', ['deleted', now(), $finding['path'], 'deleted']);
            return (int) $item['id'];
        }
        // A previous action or another finding for the same physical path may already have
        // removed the file. The requested end state is satisfied; keep the database in sync
        // instead of reporting a misleading bulk-operation failure.
        if (is_link($finding['path'])) {
            if (!@unlink($finding['path'])) throw new RuntimeException('Failed to permanently delete symbolic link.');
            DB::statement('UPDATE findings SET status=?, updated_at=? WHERE path=? AND status<>?', ['deleted', now(), $finding['path'], 'deleted']);
            return 0;
        }
        if (!is_file($finding['path'])) {
            DB::statement('UPDATE findings SET status=?, updated_at=? WHERE path=? AND status<>?', ['deleted', now(), $finding['path'], 'deleted']);
            return 0;
        }
        $id = $this->quarantine($findingId, $reason);
        $item = DB::first('SELECT * FROM quarantine_items WHERE id=?', [$id]);
        if (!$item || !is_file($item['quarantine_path']) || !@unlink($item['quarantine_path'])) {
            throw new RuntimeException('Failed to permanently delete quarantined file; it remains quarantined and can be restored.');
        }
        DB::statement('UPDATE quarantine_items SET status=?, updated_at=? WHERE id=?', ['deleted', now(), $id]);
        DB::statement('UPDATE findings SET status=?, updated_at=? WHERE path=? AND status<>?', ['deleted', now(), $finding['path'], 'deleted']);
        return $id;
    }

    public function restore(int $id): void
    {
        $item = DB::first('SELECT * FROM quarantine_items WHERE id=?', [$id]);
        if (!$item) throw new RuntimeException('Quarantine item not found.');
        if ($item['status'] !== 'quarantined') throw new RuntimeException('Item is not in quarantined state.');
        if (!is_file($item['quarantine_path'])) throw new RuntimeException('Quarantined file missing.');
        if (!is_dir(dirname($item['original_path']))) mkdir(dirname($item['original_path']), 0755, true);
        if (!rename($item['quarantine_path'], $item['original_path'])) throw new RuntimeException('Failed to restore file.');
        @chmod($item['original_path'], octdec($item['permissions'] ?: '0644'));
        DB::statement('UPDATE quarantine_items SET status=?, updated_at=? WHERE id=?', ['restored', now(), $id]);
        if ($item['finding_id']) DB::statement('UPDATE findings SET status=?, updated_at=? WHERE id=?', ['restored', now(), $item['finding_id']]);
    }
}
