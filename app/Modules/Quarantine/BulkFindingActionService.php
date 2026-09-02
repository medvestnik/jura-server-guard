<?php
namespace App\Modules\Quarantine;

use App\Support\DB;
use RuntimeException;

class BulkFindingActionService
{
    private string $directory;

    public function __construct()
    {
        $this->directory = storage_path('bulk-finding-actions');
    }

    public function create(string $action, array $ids): string
    {
        if (!in_array($action, ['quarantine', 'delete'], true)) throw new RuntimeException('Unsupported bulk action.');
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids), fn(int $id): bool => $id > 0)));
        if (!$ids) throw new RuntimeException('Nothing selected.');
        $this->ensureDirectory();
        $this->pruneOldJobs();
        $id = bin2hex(random_bytes(16));
        $now = now();
        $this->write($id, [
            'id'=>$id, 'action'=>$action, 'status'=>'queued', 'total'=>count($ids),
            'processed'=>0, 'ok'=>0, 'fail'=>0, 'current_id'=>null, 'current_path'=>null,
            'error'=>null, 'pid'=>null, 'created_at'=>$now, 'started_at'=>null,
            'finished_at'=>null, 'updated_at'=>$now, 'ids'=>$ids,
        ]);
        return $id;
    }

    public function run(string $id): array
    {
        $state = $this->read($id, true);
        if (in_array($state['status'] ?? '', ['completed', 'failed'], true)) return $this->publicState($state);
        $state['status']='running'; $state['pid']=getmypid(); $state['started_at']=$state['started_at'] ?: now(); $state['updated_at']=now();
        $this->write($id, $state);
        $service = new QuarantineService();
        try {
            foreach ($state['ids'] as $findingId) {
                $finding = DB::first('SELECT path FROM findings WHERE id=?', [(int)$findingId]);
                $state['current_id']=(int)$findingId;
                $state['current_path']=$finding['path'] ?? null;
                try {
                    if ($state['action']==='delete') $service->delete((int)$findingId, 'Background bulk web panel delete');
                    else $service->quarantine((int)$findingId, 'Background bulk web panel quarantine');
                    $state['ok']++;
                } catch (\Throwable $e) {
                    $state['fail']++;
                }
                $state['processed']++;
                $state['updated_at']=now();
                if ($state['processed'] % 10 === 0 || $state['processed'] === $state['total']) $this->write($id, $state);
            }
            $state['status']='completed'; $state['current_id']=null; $state['current_path']=null; $state['finished_at']=now(); $state['updated_at']=now();
        } catch (\Throwable $e) {
            $state['status']='failed'; $state['error']=$e->getMessage(); $state['finished_at']=now(); $state['updated_at']=now();
        }
        $this->write($id, $state);
        return $this->publicState($state);
    }

    public function status(string $id): array
    {
        $state = $this->read($id, true);
        $age = !empty($state['updated_at']) ? max(0, time()-(strtotime($state['updated_at'].' UTC') ?: time())) : 0;
        $pid = (int)($state['pid'] ?? 0);
        $alive = $pid > 0 && (function_exists('posix_kill') ? @posix_kill($pid, 0) : is_dir('/proc/'.$pid));
        if (($state['status']??'')==='running' && !$alive && $age>10) {
            $state['status']='failed'; $state['error']='Background worker stopped unexpectedly.'; $state['finished_at']=now(); $state['updated_at']=now();
            $this->write($id, $state);
        } elseif (($state['status']??'')==='queued' && $age>60) {
            $state['status']='failed'; $state['error']='Background worker did not start.'; $state['finished_at']=now(); $state['updated_at']=now();
            $this->write($id, $state);
        }
        return $this->publicState($state);
    }

    private function publicState(array $state): array
    {
        unset($state['ids']);
        return $state;
    }

    private function read(string $id, bool $withIds): array
    {
        $path = $this->path($id);
        if (!is_file($path)) throw new RuntimeException('Bulk action not found.');
        $state = json_decode((string)file_get_contents($path), true);
        if (!is_array($state)) throw new RuntimeException('Bulk action state is invalid.');
        if (!$withIds) unset($state['ids']);
        return $state;
    }

    private function write(string $id, array $state): void
    {
        $this->ensureDirectory();
        $path = $this->path($id);
        $tmp = $path.'.tmp-'.getmypid();
        $json = json_encode($state, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false || file_put_contents($tmp, $json, LOCK_EX) === false || !rename($tmp, $path)) {
            @unlink($tmp);
            throw new RuntimeException('Failed to save bulk action state.');
        }
        @chmod($path, 0600);
    }

    private function path(string $id): string
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $id)) throw new RuntimeException('Invalid bulk action id.');
        return $this->directory.'/'.$id.'.json';
    }

    private function ensureDirectory(): void
    {
        if (!is_dir($this->directory) && !mkdir($this->directory, 0700, true) && !is_dir($this->directory)) throw new RuntimeException('Failed to create bulk action directory.');
    }

    private function pruneOldJobs(): void
    {
        foreach (glob($this->directory.'/*.json') ?: [] as $path) if (@filemtime($path) < time()-604800) @unlink($path);
    }
}
