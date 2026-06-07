<?php
namespace App\Support;

class ScanLock
{
    public function __construct(private ?string $path = null)
    {
        $this->path ??= storage_path('locks/scan.lock');
    }

    public function path(): string { return $this->path; }

    public function read(): ?array
    {
        if (!is_file($this->path)) return null;
        $data = json_decode((string) @file_get_contents($this->path), true);
        return is_array($data) ? $data : ['pid' => null, 'started_at' => null, 'command' => null];
    }

    public function acquire(string $command, bool $force = false): void
    {
        if (!is_dir(dirname($this->path))) mkdir(dirname($this->path), 0750, true);
        $existing = $this->read();
        if ($existing) {
            $pid = (int) ($existing['pid'] ?? 0);
            if ($pid > 0 && $this->pidAlive($pid) && !$force) {
                throw new \RuntimeException(sprintf('Another scan is already running since %s PID %s (%s). Use --force only if the process is stale or --no-lock for debugging.', $existing['started_at'] ?? 'unknown', $pid, $existing['command'] ?? 'unknown'));
            }
            @unlink($this->path);
        }
        file_put_contents($this->path, json_encode(['pid' => getmypid(), 'started_at' => now(), 'command' => $command], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    }

    public function release(): void
    {
        $existing = $this->read();
        if (!$existing || (int) ($existing['pid'] ?? 0) === getmypid()) @unlink($this->path);
    }

    public function unlock(bool $force = false): string
    {
        $existing = $this->read();
        if (!$existing) return 'No scan lock is present.';
        $pid = (int) ($existing['pid'] ?? 0);
        if ($pid > 0 && $this->pidAlive($pid) && !$force) {
            throw new \RuntimeException(sprintf('Scan lock is active since %s PID %s. Re-run with --force to remove it anyway.', $existing['started_at'] ?? 'unknown', $pid));
        }
        @unlink($this->path);
        return 'Scan lock removed.';
    }

    private function pidAlive(int $pid): bool
    {
        if ($pid <= 0) return false;
        if (function_exists('posix_kill')) return @posix_kill($pid, 0);
        return is_dir('/proc/' . $pid);
    }
}
