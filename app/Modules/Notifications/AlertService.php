<?php
namespace App\Modules\Notifications;

use App\Modules\CronMonitor\CronMonitorService;
use App\Modules\Quarantine\QuarantineService;
use App\Support\DB;
use Throwable;

class AlertService
{
    public function __construct(private TelegramNotifier $telegram = new TelegramNotifier())
    {
    }

    public function runPostScanChecks(int $scanRunId): void
    {
        $this->sendScanNotifications($scanRunId);
        $this->autoQuarantineObviousShells($scanRunId);
    }

    public function sendScanNotifications(int $scanRunId): void
    {
        $this->notifyNewFindings($scanRunId);
        if ($this->telegram->enabled() && config('guard.notify_untrusted_webroot_files')) $this->notifyUntrustedWebrootFiles($scanRunId);
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

    public function notifyNewFindings(int $scanRunId, ?int $siteId = null): void
    {
        if (!$this->telegram->enabled() || !config('guard.notify_new_critical_high_findings')) return;
        $params = [$scanRunId];
        $siteSql = '';
        if ($siteId !== null) { $siteSql = ' AND f.site_id=?'; $params[] = $siteId; }
        $rows = DB::select("SELECT f.*, s.name site_name, u.name user_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE f.telegram_notified_at IS NULL AND f.first_seen_scan_id=? AND f.risk IN ('critical','high'){$siteSql} ORDER BY f.site_id,f.risk,f.id", $params);
        if (!$rows) return;

        $groups = [];
        foreach ($rows as $row) $groups[(string)($row['site_id'] ?? '0')][] = $row;
        foreach ($groups as $findings) {
            $critical = count(array_filter($findings, fn($f) => ($f['risk'] ?? '') === 'critical'));
            $high = count($findings) - $critical;
            $examples = array_slice($findings, 0, (int) config('guard.telegram_finding_examples'));
            $lines = [];
            foreach ($examples as $finding) {
                $path = (string)($finding['path'] ?? '?');
                if (strlen($path) > 260) $path = '…'.substr($path, -259);
                $lines[] = '• '.strtoupper((string)$finding['risk']).' '.$path;
            }
            $more = count($findings) - count($examples);
            if ($more > 0) $lines[] = "…and {$more} more finding(s)";
            $msg = "🚨 New critical/high findings\nScan: #{$scanRunId}\nUser: ".($findings[0]['user_name'] ?? '?')."\nSite: ".($findings[0]['site_name'] ?? '?')."\nCritical: {$critical}; high: {$high}; total: ".count($findings)."\n".implode("\n", $lines);
            $result = $this->telegram->send($msg);
            $ids = array_map(fn($f)=>(int)$f['id'], $findings);
            $this->markTelegramResult('findings', $ids, $result);
            $this->log('new_findings_summary', $msg, 'site', (int)($findings[0]['site_id'] ?? 0), $result);
        }
    }

    private function notifyUntrustedWebrootFiles(int $scanRunId): void
    {
        $rows = DB::select("SELECT fs.*, s.name site_name, u.name user_name FROM file_snapshots fs LEFT JOIN sites s ON s.id=fs.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE fs.telegram_notified_at IS NULL AND fs.first_seen_scan_id=? AND fs.is_missing=0 AND fs.relative_path NOT LIKE '%/%' ORDER BY fs.site_id,fs.id", [$scanRunId]);
        if (!$rows) return;
        $trusted = [];
        foreach (DB::select('SELECT ip FROM trusted_ips') as $r) $trusted[$r['ip']] = true;
        $groups = [];
        foreach ($rows as $fs) {
            $ip = $this->recentIpForPath($fs['path']);
            if ($ip !== null && isset($trusted[$ip])) {
                DB::statement('UPDATE file_snapshots SET telegram_notified_at=?,telegram_notification_error=NULL WHERE id=?', [now(),$fs['id']]);
                continue;
            }
            $fs['source_ip'] = $ip;
            $groups[(string)($fs['site_id'] ?? '0')][] = $fs;
        }
        foreach ($groups as $files) {
            $examples = array_slice($files, 0, (int)config('guard.telegram_finding_examples'));
            $lines = [];
            foreach ($examples as $file) {
                $path = (string)($file['path'] ?? '?');
                if (strlen($path) > 240) $path = '…'.substr($path, -239);
                $lines[] = '• '.$path.' — '.($file['source_ip'] ?? 'source IP unknown');
            }
            $more = count($files) - count($examples);
            if ($more > 0) $lines[] = "…and {$more} more file(s)";
            $msg = "🆕 New files in site web root\nScan: #{$scanRunId}\nUser: ".($files[0]['user_name'] ?? '?')."\nSite: ".($files[0]['site_name'] ?? '?')."\nTotal: ".count($files)."\n".implode("\n",$lines);
            $result = $this->telegram->send($msg);
            $ids = array_map(fn($f)=>(int)$f['id'],$files);
            $this->markTelegramResult('file_snapshots', $ids, $result);
            $this->log('untrusted_webroot_summary',$msg,'site',(int)($files[0]['site_id']??0),$result);
        }
    }

    private function markTelegramResult(string $table, array $ids, array $result): void
    {
        if (!in_array($table, ['findings','file_snapshots'], true)) return;
        foreach (array_chunk($ids, 500) as $chunk) {
            $placeholders = implode(',', array_fill(0, count($chunk), '?'));
            if ($result['ok']) {
                DB::statement("UPDATE {$table} SET telegram_notified_at=?,telegram_notification_error=NULL WHERE id IN ({$placeholders})", array_merge([now()], $chunk));
            } else {
                $error = substr((string)($result['error'] ?? 'Telegram delivery failed.'), 0, 1000);
                DB::statement("UPDATE {$table} SET telegram_notification_error=? WHERE id IN ({$placeholders})", array_merge([$error], $chunk));
            }
        }
    }

    private function autoQuarantineObviousShells(int $scanRunId): void
    {
        if (!config('guard.auto_quarantine_obvious_shells')) return;
        $rows = DB::select("SELECT f.*, s.name site_name, u.name user_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE f.first_seen_scan_id=? AND f.risk='critical' AND f.status='new'", [$scanRunId]);
        if (!$rows) return;
        $trusted = [];
        foreach (DB::select('SELECT ip FROM trusted_ips') as $r) $trusted[$r['ip']] = true;
        $quarantine = new QuarantineService();
        foreach ($rows as $f) {
            $reason = $this->classifyObviousShell($f, $trusted);
            if ($reason === null) continue;
            try {
                $quarantine->quarantine((int) $f['id'], 'Auto-quarantine: ' . $reason);
                $msg = "🔒 Auto-quarantined obvious shell\nUser: " . ($f['user_name'] ?? '?') . "\nSite: " . ($f['site_name'] ?? '?') . "\nPath: {$f['path']}\nReason: {$reason}";
                $result = $this->telegram->send($msg);
                $this->log('auto_quarantine', $msg, 'finding', (int) $f['id'], $result);
            } catch (Throwable $e) {
                // Leave the finding as 'new' so it still surfaces for manual handling.
            }
        }
    }

    /** Returns a human-readable reason to auto-quarantine, or null to leave the finding alone. */
    private function classifyObviousShell(array $finding, array $trustedIps): ?string
    {
        if (!empty($finding['matched_signature_name'])) {
            return 'matched known signature "' . $finding['matched_signature_name'] . '"';
        }
        $ip = $this->recentIpForPath($finding['path']);
        if ($ip !== null && !isset($trustedIps[$ip])) {
            return 'uploaded from untrusted IP ' . $ip;
        }
        return null;
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
