<?php
namespace App\Modules\Notifications;

use App\Modules\CronMonitor\CronMonitorService;
use App\Support\DB;

class AlertService
{
    public function __construct(private TelegramNotifier $telegram = new TelegramNotifier())
    {
    }

    public function runPostScanChecks(int $scanRunId): void
    {
        if (!$this->telegram->enabled()) return;
        if (config('guard.notify_new_critical_high_findings')) $this->notifyNewFindings($scanRunId);
        if (config('guard.notify_untrusted_webroot_files')) $this->notifyUntrustedWebrootFiles($scanRunId);
    }

    /**
     * Scans crontabs for new entries and, if enabled, notifies about each one found.
     * @param array|null $newLines Pass a pre-computed list from CronMonitorService::scan() to avoid
     *     scanning crontabs twice; when null, this method performs the scan itself.
     * @return array the new cron entries found (same shape as CronMonitorService::scan())
     */
    public function runCronCheck(?array $newLines = null): array
    {
        $newLines ??= (new CronMonitorService())->scan();
        if ($newLines && $this->telegram->enabled() && config('guard.notify_cron_changes')) {
            foreach ($newLines as $entry) {
                $msg = "🕓 New cron job detected\nUser: {$entry['server_user']}\nLine: {$entry['line']}";
                $result = $this->telegram->send($msg);
                DB::statement('UPDATE cron_snapshots SET notified_at=? WHERE id=?', [now(), $entry['id']]);
                $this->log('cron_change', $msg, 'cron_snapshot', (int) $entry['id'], $result);
            }
        }
        return $newLines;
    }

    private function notifyNewFindings(int $scanRunId): void
    {
        $rows = DB::select("SELECT f.*, s.name site_name, u.name user_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE f.first_seen_scan_id=? AND f.risk IN ('critical','high')", [$scanRunId]);
        foreach ($rows as $f) {
            $msg = "🚨 New {$f['risk']} finding\nType: {$f['type']}\nUser: " . ($f['user_name'] ?? '?') . "\nSite: " . ($f['site_name'] ?? '?') . "\nPath: {$f['path']}\nTitle: {$f['title']}";
            $result = $this->telegram->send($msg);
            $this->log('new_finding', $msg, 'finding', (int) $f['id'], $result);
        }
    }

    private function notifyUntrustedWebrootFiles(int $scanRunId): void
    {
        $rows = DB::select("SELECT fs.*, s.name site_name, u.name user_name FROM file_snapshots fs LEFT JOIN sites s ON s.id=fs.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE fs.first_seen_scan_id=? AND fs.is_missing=0 AND fs.relative_path NOT LIKE '%/%'", [$scanRunId]);
        if (!$rows) return;
        $trusted = [];
        foreach (DB::select('SELECT ip FROM trusted_ips') as $r) $trusted[$r['ip']] = true;
        foreach ($rows as $fs) {
            $ip = $this->recentIpForPath($fs['path']);
            if ($ip !== null && isset($trusted[$ip])) continue;
            $ipText = $ip ?? 'unknown (no matching log line found)';
            $msg = "🆕 New file in site web root\nUser: " . ($fs['user_name'] ?? '?') . "\nSite: " . ($fs['site_name'] ?? '?') . "\nPath: {$fs['path']}\nSource IP: {$ipText}" . ($ip !== null ? ' (not in trusted IPs)' : '');
            $result = $this->telegram->send($msg);
            $this->log('untrusted_webroot_file', $msg, 'file_snapshot', (int) $fs['id'], $result);
        }
    }

    private function recentIpForPath(string $path): ?string
    {
        $base = basename($path);
        if ($base === '') return null;
        $row = DB::first('SELECT ip FROM log_events WHERE uri LIKE ? ORDER BY id DESC LIMIT 1', ['%' . $base . '%']);
        return $row['ip'] ?? null;
    }

    private function log(string $category, string $message, string $relatedType, int $relatedId, array $result): void
    {
        DB::insert('INSERT INTO notifications_log (channel,category,message,related_type,related_id,status,error_text,created_at) VALUES (?,?,?,?,?,?,?,?)', [
            'telegram', $category, $message, $relatedType, $relatedId, $result['ok'] ? 'sent' : 'failed', $result['error'] ?? null, now(),
        ]);
    }
}
