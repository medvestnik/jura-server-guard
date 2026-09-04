<?php
namespace App\Modules\Scanner;

use App\Modules\CronMonitor\CronMonitorService;
use App\Modules\Inventory\InventoryService;
use App\Modules\LogAnalyzer\LogAnalyzerService;
use App\Modules\Notifications\AlertService;
use App\Modules\Rules\RuleRepository;
use App\Support\DB;
use App\Support\ScanLock;
use App\Modules\Scanner\SignatureEngine;
use App\Modules\Scanner\CmsDetector;
use AppendIterator;
use ArrayIterator;
use FilesystemIterator;
use Iterator;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Throwable;
use SplFileInfo;

class ScannerService
{
    private int $skippedDirectories = 0;
    private int $skippedMedia = 0;
    private bool $limitReached = false;
    private int $lastDbProgressFiles = 0;
    private int $lastDbProgressAt = 0;
    private array $diffStats = ['files_seen_total'=>0,'files_new'=>0,'files_modified'=>0,'files_deleted'=>0,'files_changed_total'=>0,'files_analyzed'=>0,'files_skipped_unchanged'=>0];
    private ?array $activeFindingPathHashes = null;
    private ?array $highRiskFindingPathHashes = null;
    private array $signatureHitCounts = [];
    private array $noisySignatures = [];
    public function __construct(private ?RuleRepository $rules = null) { $this->rules ??= new RuleRepository(); }

    public function scan(string $scopeType = 'full', ?string $scopeValue = null, array $options = []): int
    {
        $profile = $this->profile($options);
        $this->diffStats = ['files_seen_total'=>0,'files_new'=>0,'files_modified'=>0,'files_deleted'=>0,'files_changed_total'=>0,'files_analyzed'=>0,'files_skipped_unchanged'=>0];
        $this->signatureHitCounts = [];
        $this->noisySignatures = [];
        $this->activeFindingPathHashes = null;
        $this->highRiskFindingPathHashes = null;
        $scanMode = $this->scanMode($options);
        $previousRunId = $this->previousRunId($scopeType, $scopeValue);
        $pid = getmypid() ?: null;
        $deadlineAt = $this->deadlineAt($options);
        $options['deadline_at'] = $deadlineAt;
        $totalEstimated = $this->scanMode($options) === 'changed_only' ? null : $this->estimateTotalFiles($scopeType, $scopeValue, $options);
        $runId = DB::insert('INSERT INTO scan_runs (started_at,status,scope_type,scope_value,profile,pid,total_files_estimated,last_heartbeat_at,progress_message,scan_mode,previous_scan_id,files_scanned,skipped_media,skipped_directories,findings_count,findings_new,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,0,0,0,0,0,?,?)', [now(),'running',$scopeType,$scopeValue,$profile,$pid,$totalEstimated,now(),'Starting scan',$scanMode,$previousRunId,now(),now()]);
        $files = 0; $findings = 0;
        $stop = function (string $signal) use (&$runId, &$files, &$findings): void {
            DB::statement('UPDATE scan_runs SET status=?, finished_at=?, files_scanned=?, findings_count=?, findings_new=?, skipped_media=?, skipped_directories=?, error_text=?, last_heartbeat_at=?, progress_message=?, updated_at=? WHERE id=?', ['stopped', now(), $files, $findings, $findings, $this->skippedMedia, $this->skippedDirectories, $signal, now(), $signal, now(), $runId]);
            (new ScanLock())->release();
            exit(130);
        };
        if (function_exists('pcntl_async_signals')) {
            pcntl_async_signals(true);
            pcntl_signal(SIGTERM, fn() => $stop('Stopped by SIGTERM'));
            pcntl_signal(SIGINT, fn() => $stop('Stopped by SIGINT'));
        }
        try {
            $GLOBALS['__guard_scan_run_id'] = $runId;
            $inv = new InventoryService();
            $alerts = new AlertService();
            $sites = match ($scopeType) { 'user' => $inv->refresh($scopeValue, null, $options), 'site' => $inv->refresh(null, $scopeValue, $options), default => $inv->refresh(null, null, $options) };
            $this->progress($options, sprintf('Scan #%d [%s/%s]: %d site(s) selected for %s%s', $runId, $this->profile($options), $scanMode, count($sites), $scopeType, $scopeValue ? ': '.$scopeValue : ''));
            foreach ($sites as $site) {
                if ($this->deadlineReached($options)) { $this->limitReached = true; break; }
                [$f, $c] = $this->scanSite($site, $runId, $options, $files, $findings); $files += $f; $findings += $c;
                DB::statement('UPDATE sites SET last_scan_at=?, updated_at=? WHERE id=?', [now(), now(), $site['id']]);
                if (empty($options['dry_run'])) {
                    try { $alerts->notifyNewFindings($runId, (int)$site['id']); }
                    catch (Throwable $e) { $this->progress($options, 'Telegram finding alert failed: '.$e->getMessage()); }
                }
                if ($this->limitReached) break;
            }
            if ($this->shouldRunLogAnalysis($options) && !$this->deadlineReached($options) && !$this->limitReached) {
                $this->updateRunProgress($runId, $files, $findings, null, null, 'Running log analysis', true);
                $this->progress($options, 'Running log analysis');
                (new LogAnalyzerService())->analyze(['deadline_at'=>$deadlineAt, 'site_paths'=>array_column($sites, 'path'), 'heartbeat'=>fn() => $this->updateRunProgress($runId, $files, $findings, null, null, 'Running log analysis')]);
            } elseif ($this->deadlineReached($options)) {
                $this->limitReached = true;
            } else {
                $msg = $this->logSkipMessage($options);
                $this->updateRunProgress($runId, $files, $findings, null, null, $msg, true);
                $this->progress($options, $msg);
            }
            $this->updateRunProgress($runId, $files, $findings, null, null, 'Finalizing scan', true);
            $this->progress($options, 'Finalizing scan');
            $status = $this->limitReached ? 'completed_with_limit' : 'completed';
            $error = $this->limitReached ? 'Stopped by max files or max seconds; scan may be incomplete.' : null;
            DB::statement('UPDATE scan_runs SET status=?, finished_at=?, files_scanned=?, findings_count=?, findings_new=?, skipped_media=?, skipped_directories=?, error_text=?, last_heartbeat_at=?, progress_message=?, files_seen_total=?, files_new=?, files_modified=?, files_deleted=?, files_changed_total=?, files_analyzed=?, files_skipped_unchanged=?, diff_summary=?, updated_at=? WHERE id=?', [$status, now(), $files, $findings, $findings, $this->skippedMedia, $this->skippedDirectories, $error, now(), ucfirst(str_replace('_',' ', $status)), $this->diffStats['files_seen_total'], $this->diffStats['files_new'], $this->diffStats['files_modified'], $this->diffStats['files_deleted'], $this->diffStats['files_changed_total'], $this->diffStats['files_analyzed'], $this->diffStats['files_skipped_unchanged'], json_encode(array_merge($this->diffStats, ['noisy_signatures'=>$this->noisySignatures]), JSON_UNESCAPED_SLASHES), now(), $runId]);
            $msg = $this->limitReached ? 'Scan stopped by max seconds or max files' : 'Scan completed';
            $this->progress($options, $msg);
            $this->progress($options, "Scan #$runId $status: files=$files findings=$findings skipped_media={$this->skippedMedia} skipped_directories={$this->skippedDirectories} files_seen_total={$this->diffStats['files_seen_total']} files_new={$this->diffStats['files_new']} files_modified={$this->diffStats['files_modified']} files_deleted={$this->diffStats['files_deleted']} files_analyzed={$this->diffStats['files_analyzed']} files_skipped_unchanged={$this->diffStats['files_skipped_unchanged']} scan_mode=$scanMode noisy_signatures=".json_encode($this->noisySignatures, JSON_UNESCAPED_SLASHES));
            if (empty($options['dry_run'])) {
                try {
                    $alerts->runPostScanChecks($runId);
                    if (config('guard.cron_monitor_enabled')) $alerts->runCronCheck();
                } catch (Throwable $e) {
                    $this->progress($options, 'Alert/cron check failed: ' . $e->getMessage());
                }
            }
            return $runId;
        } catch (Throwable $e) {
            DB::statement('UPDATE scan_runs SET status=?, finished_at=?, files_scanned=?, findings_count=?, findings_new=?, skipped_media=?, skipped_directories=?, error_text=?, last_heartbeat_at=?, progress_message=?, updated_at=? WHERE id=?', ['failed', now(), $files, $findings, $findings, $this->skippedMedia, $this->skippedDirectories, $e->getMessage(), now(), 'Scan failed', now(), $runId]);
            throw $e;
        }
    }

    private function scanSite(array $site, int $runId, array $options, int $baseFiles = 0, int $baseFindings = 0): array
    {
        if ($this->scanMode($options) === 'changed_only') return $this->scanSiteChangedOnly($site, $runId, $options, $baseFiles, $baseFindings);
        $start = time(); $count = 0; $findings = 0; $seen = []; $mode = $this->scanMode($options);
        $maxFiles = (int)($options['max_files'] ?? config('guard.max_files_per_site'));
        $maxSeconds = (int)($options['max_seconds'] ?? config('guard.max_scan_seconds_per_site'));
        $dryRun = (bool)($options['dry_run'] ?? false);
        $cms = $this->detectCmsForSite($site);
        $site = array_merge($site, ['cms_type'=>$cms['type'], 'cms_version'=>$cms['version'], 'cms_confidence'=>$cms['confidence']]);
        $this->progress($options, "Scanning files for site {$site['name']} ({$site['path']})");
        $this->updateRunProgress($runId, $baseFiles, $baseFindings, $site['name'] ?? null, $site['path'] ?? null, "Scanning files", true);
        $it = $this->orderedIterator($site['path'], $options);
        foreach ($it as $file) {
            if ($maxFiles > 0 && $count >= $maxFiles) { $this->limitReached = true; $this->progress($options, "Max files reached for {$site['name']}: $maxFiles"); break; }
            if ($this->deadlineReached($options)) { $this->limitReached = true; $this->progress($options, "Max seconds reached for scan run while scanning {$site['name']}: $maxSeconds"); break; }
            if (!$file->isFile() || $file->isLink()) continue;
            $path = $file->getPathname();
            if (!$this->shouldScanFile($path, $site['path'], $options)) { $this->skippedMedia++; $this->updateRunProgress($runId, $baseFiles + $count, $baseFindings + $findings, $site['name'] ?? null, $path, 'Skipping non-eligible/media file'); continue; }
            $seen[$path] = true; $count++;
            $relative = ltrim(str_replace($site['path'], '', $path), '/');
            $pathHash = hash('sha256', $path);
            $previous = DB::first('SELECT * FROM file_snapshots WHERE path_hash=? AND path=?', [$pathHash, $path]);
            $meta = $this->meta($path, $previous, $relative, $options);
            $change = $dryRun ? 'dry-run' : $this->snapshot($site['id'], $path, $pathHash, $relative, $meta, $previous);
            $this->accountDiff($change);
            $analyze = $mode === 'full' || $change !== 'same' || ($mode !== 'changed_only' && $this->heavyAnalysisCandidate($path, $site['path'], $relative, $meta)) || (($options['paranoid'] ?? false) && $this->paranoidRecheckCandidate($path, $relative)) || $this->mustAnalyzeChangedOnly($path, $site['path'], $relative, $options);
            if (!$analyze) { $this->diffStats['files_skipped_unchanged']++; continue; }
            $this->diffStats['files_analyzed']++;
            foreach ($this->detect($site, $path, $relative, $meta, $change, $options) as $finding) {
                if (!$dryRun) $this->upsertFinding($runId, $site['id'], $path, $meta, $finding);
                $findings++;
            }
            if ($count % 100 === 0) $this->updateRunProgress($runId, $baseFiles + $count, $baseFindings + $findings, $site['name'] ?? null, $path, "Scanning {$site['name']}");
            if ($count % 1000 === 0) $this->progress($options, "Progress {$site['name']}: files=$count findings=$findings elapsed=".(time()-$start).'s');
        }
        if (!$dryRun) foreach (DB::select('SELECT id,path FROM file_snapshots WHERE site_id=? AND is_missing=0', [$site['id']]) as $snap) if (!isset($seen[$snap['path']]) && !file_exists($snap['path'])) { $this->diffStats['files_deleted']++; $this->diffStats['files_changed_total']++; DB::statement('UPDATE file_snapshots SET is_missing=1,last_changed_at=?,last_changed_scan_id=?,updated_at=? WHERE id=?', [now(),$runId,now(),$snap['id']]); }
        $this->updateRunProgress($runId, $baseFiles + $count, $baseFindings + $findings, $site['name'] ?? null, $site['path'] ?? null, "Finished file scan for site {$site['name']}", true);
        $this->progress($options, "Finished file scan for site {$site['name']}: files=$count findings=$findings skipped_media={$this->skippedMedia} skipped_directories={$this->skippedDirectories} elapsed=".(time()-$start).'s');
        return [$count, $findings];
    }


    private function scanSiteChangedOnly(array $site, int $runId, array $options, int $baseFiles = 0, int $baseFindings = 0): array
    {
        $siteStart = microtime(true); $t = ['inventory_time'=>0,'manifest_compare_time'=>0,'diff_time'=>0,'candidate_selection_time'=>0,'content_scan_time'=>0,'finalize_time'=>0];
        $findings = 0; $dryRun = (bool)($options['dry_run'] ?? false);
        $cms = $this->detectCmsForSite($site);
        $site = array_merge($site, ['cms_type'=>$cms['type'], 'cms_version'=>$cms['version'], 'cms_confidence'=>$cms['confidence']]);
        $this->progress($options, "Scanning files for site {$site['name']} ({$site['path']})");
        $this->updateRunProgress($runId, $baseFiles, $baseFindings, $site['name'] ?? null, $site['path'] ?? null, 'Building fast site manifest', true);

        $a = microtime(true); $manifest = $this->buildSiteManifest($site['path'], $options); $t['inventory_time'] = microtime(true) - $a;
        $files = array_values(array_filter($manifest['entries'], fn($e) => $e['type'] === 'file'));
        $dirs = count($manifest['entries']) - count($files);
        $count = count($files);
        $this->diffStats['files_seen_total'] += $count;
        $this->skippedMedia += count(array_filter($files, fn($e) => $this->isOrdinaryMedia($e['path'])));
        $this->progress($options, sprintf('Inventory completed: files=%d dirs=%d elapsed=%ds', $count, $dirs, (int)round($t['inventory_time'])));

        $a = microtime(true); $previous = $this->previousCompletedManifest($site['id']); $t['manifest_compare_time'] = microtime(true) - $a;
        if ($previous && ($previous['site_manifest_hash'] ?? null) === $manifest['site_manifest_hash']) {
            $this->diffStats['files_skipped_unchanged'] += $count;
            $this->progress($options, 'Manifest unchanged: skipped content analysis');
            $this->progress($options, 'No file changes detected; skipped content analysis');
            $this->writeManifestSummary($runId, $site['id'], $manifest, $t + ['elapsed'=>microtime(true)-$siteStart, 'message'=>'No file changes detected; skipped content analysis']);
            return [$count, 0];
        }

        $a = microtime(true); $previousRows = $this->loadSnapshotMap($site['id']); $t['diff_time'] = microtime(true) - $a;
        $needsBaselineRefresh = $previousRows && $this->snapshotMapNeedsMetadataBaseline($previousRows);
        $new=[]; $modified=[]; $unchanged=[]; $currentByPathHash=[];
        foreach ($files as $entry) {
            $currentByPathHash[$entry['path_hash']] = $entry;
            $row = $previousRows[$entry['path_hash']] ?? null;
            if (!$row) $new[] = $entry;
            elseif ($needsBaselineRefresh || $this->manifestMetadataUnchanged($row, $entry)) $unchanged[] = $entry;
            else $modified[] = $entry;
        }
        $deleted = [];
        foreach ($previousRows as $hash => $row) if (!isset($currentByPathHash[$hash]) && empty($row['is_missing'])) $deleted[] = $row;
        if ($needsBaselineRefresh) { $new = []; $modified = []; $deleted = []; $unchanged = $files; }
        $this->diffStats['files_new'] += count($new); $this->diffStats['files_modified'] += count($modified); $this->diffStats['files_deleted'] += count($deleted);
        $this->diffStats['files_changed_total'] += count($new) + count($modified) + count($deleted);
        $this->diffStats['files_skipped_unchanged'] += count($unchanged);
        $this->progress($options, sprintf('Diff completed: new=%d modified=%d deleted=%d unchanged=%d elapsed=%ds%s', count($new), count($modified), count($deleted), count($unchanged), (int)round($t['diff_time']), $needsBaselineRefresh ? ' (Snapshot schema changed; refreshed baseline)' : ''));

        $a = microtime(true); $forced = $this->changedOnlyForcedHashes($site['path'], $options); $candidates=[];
        foreach (array_merge($new, $modified) as $e) if ($this->shouldScanFile($e['path'], $site['path'], $options)) $candidates[$e['path_hash']] = $e;
        foreach ($files as $e) if (isset($forced[$e['path_hash']]) || (($options['paranoid'] ?? false) && $this->paranoidRecheckCandidate($e['path'], $e['relative_path']))) $candidates[$e['path_hash']] = $e;
        $t['candidate_selection_time'] = microtime(true) - $a;

        $a = microtime(true);
        foreach ($candidates as $entry) {
            if ($this->deadlineReached($options)) { $this->limitReached = true; break; }
            $meta = $this->metaFromManifestEntry($entry, $previousRows[$entry['path_hash']] ?? null);
            $change = isset($previousRows[$entry['path_hash']]) ? 'changed' : 'new';
            $this->diffStats['files_analyzed']++;
            foreach ($this->detect($site, $entry['path'], $entry['relative_path'], $meta, $change, $options) as $finding) {
                if (!$dryRun) $this->upsertFinding($runId, $site['id'], $entry['path'], $meta, $finding);
                $findings++;
            }
        }
        $t['content_scan_time'] = microtime(true) - $a;
        $this->progress($options, sprintf('Content scan completed: candidates=%d findings=%d elapsed=%ds', count($candidates), $findings, (int)round($t['content_scan_time'])));

        $a = microtime(true);
        if (!$dryRun) { $this->refreshSnapshotsFromManifest($site['id'], $runId, $files, $previousRows, $currentByPathHash, $deleted); $this->writeManifestSummary($runId, $site['id'], $manifest, $t + ['elapsed'=>microtime(true)-$siteStart, 'baseline_refreshed'=>$needsBaselineRefresh]); }
        $t['finalize_time'] = microtime(true) - $a;
        if ($needsBaselineRefresh) $this->progress($options, 'Snapshot schema changed; refreshed baseline');
        $this->progress($options, sprintf('Changed-only timings: inventory_time=%.3fs manifest_compare_time=%.3fs diff_time=%.3fs candidate_selection_time=%.3fs content_scan_time=%.3fs finalize_time=%.3fs', $t['inventory_time'], $t['manifest_compare_time'], $t['diff_time'], $t['candidate_selection_time'], $t['content_scan_time'], $t['finalize_time']));
        $this->updateRunProgress($runId, $baseFiles + $count, $baseFindings + $findings, $site['name'] ?? null, $site['path'] ?? null, "Finished changed-only scan for site {$site['name']}", true);
        $this->progress($options, "Finished file scan for site {$site['name']}: files=$count findings=$findings skipped_media={$this->skippedMedia} skipped_directories={$this->skippedDirectories} elapsed=".(int)round(microtime(true)-$siteStart).'s');
        return [$count, $findings];
    }


    private function updateRunProgress(int $runId, int $files, int $findings, ?string $site, ?string $path, string $message, bool $force = false): void
    {
        $now = time();
        if (!$force && ($files - $this->lastDbProgressFiles) < 100 && ($now - $this->lastDbProgressAt) < 3) return;
        $this->lastDbProgressAt = $now;
        $this->lastDbProgressFiles = $files;
        DB::statement('UPDATE scan_runs SET files_scanned=?, findings_count=?, findings_new=?, skipped_media=?, skipped_directories=?, current_site=?, current_path=?, last_heartbeat_at=?, progress_message=?, updated_at=? WHERE id=?', [$files, $findings, $findings, $this->skippedMedia, $this->skippedDirectories, $site, $path, now(), $message, now(), $runId]);
    }

    private function estimateTotalFiles(string $scopeType, ?string $scopeValue, array $options): ?int
    {
        try {
            $inv = new InventoryService();
            $sites = match ($scopeType) { 'user' => $inv->refresh($scopeValue, null, $options), 'site' => $inv->refresh(null, $scopeValue, $options), default => $inv->refresh(null, null, $options) };
            $total = 0;
            foreach ($sites as $site) {
                if ($this->deadlineReached($options)) { $this->limitReached = true; break; }
                $it = new RecursiveIteratorIterator($this->filteredIterator($site['path'], $options));
                foreach ($it as $file) {
                    if ($this->deadlineReached($options)) { $this->limitReached = true; break; }
                    if ($file instanceof SplFileInfo && $file->isFile() && !$file->isLink() && $this->shouldScanFile($file->getPathname(), $site['path'], $options)) $total++;
                }
            }
            $this->skippedDirectories = 0;
            $this->skippedMedia = 0;
            return $total;
        } catch (Throwable) { return null; }
    }


    private function profile(array $options): string
    {
        $profile = strtolower((string)($options['profile'] ?? config('guard.scan_profile', 'fast')));
        return in_array($profile, ['fast','standard','deep'], true) ? $profile : 'fast';
    }

    private function shouldScanFile(string $path, string $root, array $options): bool
    {
        $profile = $this->profile($options);
        if ($this->scanMode($options) === 'changed_only') return !$this->isOrdinaryMedia($path) || $profile === 'deep';
        if ($profile === 'deep') return true;
        $rel = ltrim(str_replace($root, '', $path), '/');
        if ($this->isValidationPath($path) || $this->isRootCriticalFile($rel) || $this->isWebConfig($path) || $this->isPhpLike($path)) return true;
        $lower = strtolower($path);
        if ($profile === 'fast') return false;
        if (preg_match('/\.(js|html?|shtml|svg|txt)$/i', $path)) return true;
        if (@is_executable($path)) return true;
        if ($this->isOrdinaryMedia($path)) {
            $recent = @filemtime($path) && @filemtime($path) > time() - 14 * 86400;
            return $recent && (preg_match('/(shell|cmd|upload|alfa|eval|pki|acme)/i', basename($path)) || $this->hasPhpMarker($path));
        }
        return $this->hasPhpMarker($path) || str_contains($lower, '.php.');
    }

    private function isPhpLike(string $path): bool { return (bool)preg_match('/\.(php|phtml|phar|php5|php7|php8|inc)$/i', $path); }
    private function isWebConfig(string $path): bool { return (bool)preg_match('/(^|\/)(\.htaccess|\.user\.ini|php\.ini|web\.config|nginx\.conf)$/i', $path); }
    private function isRootCriticalFile(string $rel): bool { return (bool)preg_match('/(^|\/)(index\.php|wp-config\.php|configuration\.php|config\.php)$/i', $rel); }
    private function isOrdinaryMedia(string $path): bool { return (bool)preg_match('/\.(jpe?g|png|gif|webp|ico|mp4|webm|avi|mov|pdf)$/i', $path) || (bool)preg_match('/-\d{2,4}x\d{2,4}\.(jpe?g|png|webp)$/i', $path); }
    private function isValidationPath(string $path): bool { return (bool)preg_match('#/(\.well-known|well-known|pki-validation|acme-challenge)(/|$)#i', $path); }
    private function fakeWellKnownPath(string $path): bool { return (bool)preg_match('#/well-known(/|$)#i', $path); }
    private function hasPhpMarker(string $path): bool { if ((@filesize($path) ?: 0) > 1024 * 1024) return false; $c = @file_get_contents($path, false, null, 0, 65536) ?: ''; return stripos($c, '<?php') !== false || stripos($c, '<?=') !== false; }

    private function shouldSkipDirectory(string $path, string $name, array $options): bool
    {
        $lower = strtolower($name);
        if (!($options['include_old'] ?? config('guard.scan_old_dubl_by_default')) && (str_contains($lower, 'old') || str_contains($lower, 'dubl'))) return true;
        if (!($options['include_storage'] ?? config('guard.scan_storage_by_default')) && $lower === 'storage') return true;
        if (!($options['include_backups'] ?? false) && (str_contains($lower, 'backup') || str_contains($lower, 'bak'))) return true;
        foreach (config('guard.exclude_paths') as $pattern) if (fnmatch($pattern, $path.'/', FNM_CASEFOLD)) return true;
        if (!($options['include_vendor'] ?? config('guard.scan_vendor_by_default'))) foreach (config('guard.exclude_vendor_paths') as $pattern) if (fnmatch($pattern, $path.'/', FNM_CASEFOLD)) return true;
        return false;
    }

    private function isPriorityDirectory(string $name): bool
    {
        $lower = strtolower($name);
        foreach (config('guard.priority_dir_names') as $keyword) if (str_contains($lower, $keyword)) return true;
        return false;
    }

    private function filteredIterator(string $root, array $options, array $excludeDirs = [], array $excludeFiles = []): RecursiveCallbackFilterIterator
    {
        $dir = new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS);
        return new RecursiveCallbackFilterIterator($dir, function ($current) use ($options, $excludeDirs, $excludeFiles) {
            $path = $current->getPathname();
            if ($current->isDir()) {
                if (isset($excludeDirs[$path])) return false;
                if ($this->shouldSkipDirectory($path, $current->getFilename(), $options)) { $this->skippedDirectories++; return false; }
                return true;
            }
            return !isset($excludeFiles[$path]);
        });
    }

    /** Public accessor so other services (e.g. a targeted signature sweep) can reuse the
     *  same directory exclusion rules (old/dubl/backup/storage/vendor/noise) as a normal scan. */
    public function directoryIterator(string $root, array $options = []): RecursiveIteratorIterator
    {
        return new RecursiveIteratorIterator($this->filteredIterator($root, $options));
    }

    /** How many directory levels below a site root to look for nested priority directories
     *  (e.g. wp-content/uploads) before giving up and leaving deeper ones in normal walk order. */
    private const PRIORITY_SCAN_MAX_DEPTH = 6;

    /**
     * Walks a site root with likely-webshell-drop directories (tmp/cache/uploads/images/...)
     * visited before everything else, so a fresh shell surfaces early in a scan instead of
     * after the scanner has worked through a CMS's own (much larger, much less often abused)
     * library/admin/module code. Priority directories are hoisted wherever they appear in the
     * tree (e.g. WordPress's wp-content/uploads), not just at the site root, since their
     * immediate parent is rarely priority-named itself.
     */
    private function orderedIterator(string $root, array $options): Iterator
    {
        $rootFiles = [];
        foreach (@scandir($root) ?: [] as $name) {
            if ($name === '.' || $name === '..') continue;
            $full = rtrim($root, '/') . '/' . $name;
            if (is_link($full)) continue;
            if (is_file($full)) $rootFiles[] = new SplFileInfo($full);
        }
        $priorityDirs = [];
        $this->collectPriorityDirectories($root, $options, 0, $priorityDirs);
        $rootFilePaths = [];
        foreach ($rootFiles as $f) $rootFilePaths[$f->getPathname()] = true;

        $append = new AppendIterator();
        $append->append(new ArrayIterator($rootFiles));
        foreach ($priorityDirs as $dir) $append->append(new RecursiveIteratorIterator($this->filteredIterator($dir, $options)));
        $append->append(new RecursiveIteratorIterator($this->filteredIterator($root, $options, $priorityDirs, $rootFilePaths)));
        return $append;
    }

    /** Recursively finds priority-named directories anywhere under $dir (bounded by depth),
     *  keyed by absolute path so orderedIterator() can both walk them first and exclude their
     *  subtrees from the normal walk that follows. Stops descending once a directory itself is
     *  classified as priority, since it (and everything under it) is already covered by the
     *  hoisted walk. */
    private function collectPriorityDirectories(string $dir, array $options, int $depth, array &$found): void
    {
        if ($depth > self::PRIORITY_SCAN_MAX_DEPTH) return;
        foreach (@scandir($dir) ?: [] as $name) {
            if ($name === '.' || $name === '..') continue;
            $full = rtrim($dir, '/') . '/' . $name;
            if (!is_dir($full) || is_link($full)) continue;
            if ($this->shouldSkipDirectory($full, $name, $options)) continue;
            if ($this->isPriorityDirectory($name)) { $found[$full] = $full; continue; }
            $this->collectPriorityDirectories($full, $options, $depth + 1, $found);
        }
    }

    private function meta(string $path, ?array $previous = null, string $relative = '', array $options = []): array
    {
        $stat = @stat($path) ?: [];
        $inode = isset($stat['ino']) ? (string)$stat['ino'] : null; $mode = isset($stat['mode']) ? (string)$stat['mode'] : null; $uid = isset($stat['uid']) ? (string)$stat['uid'] : null; $gid = isset($stat['gid']) ? (string)$stat['gid'] : null; $ctime = isset($stat['ctime']) ? gmdate('Y-m-d H:i:s',$stat['ctime']) : null;
        $size = @filesize($path) ?: 0;
        $mtime = isset($stat['mtime']) ? gmdate('Y-m-d H:i:s',$stat['mtime']) : null;
        $owner = function_exists('posix_getpwuid') ? (posix_getpwuid($stat['uid'] ?? 0)['name'] ?? (string)($stat['uid'] ?? '')) : (string)($stat['uid'] ?? '');
        $group = function_exists('posix_getgrgid') ? (posix_getgrgid($stat['gid'] ?? 0)['name'] ?? (string)($stat['gid'] ?? '')) : (string)($stat['gid'] ?? '');
        $permissions = substr(sprintf('%o', @fileperms($path)), -4);
        $sha = $previous['sha256'] ?? null;
        if ($this->scanMode($options) === 'full' || $this->shouldHash($path, $relative, $size, $previous, $mtime, $permissions, $owner, $options)) $sha = @hash_file('sha256',$path) ?: null;
        return ['size'=>$size, 'mtime'=>$mtime, 'ctime'=>$ctime, 'inode'=>$inode, 'mode'=>$mode, 'uid'=>$uid, 'gid'=>$gid, 'extension'=>strtolower(pathinfo($path, PATHINFO_EXTENSION)), 'file_category'=>$this->fileCategory($path, $relative), 'sha256'=>$sha, 'owner'=>$owner, 'group'=>$group, 'permissions'=>$permissions];
    }

    private function shouldHash(string $path, string $rel, int $size, ?array $previous, ?string $mtime, string $permissions, string $owner, array $options = []): bool
    {
        if ($size > ((int)config('guard.max_file_size_for_hash_mb') * 1024 * 1024)) return false;
        if (!$previous) return true;
        $metadataChanged = (int)$previous['size'] !== $size || (string)$previous['mtime'] !== (string)$mtime || (string)$previous['permissions'] !== $permissions || (string)$previous['owner'] !== $owner;
        if (!$metadataChanged) return false;
        if ($this->scanMode($options) === 'changed_only') return true;
        if (config('guard.hash_all_files')) return true;
        $isPhp = (bool)preg_match('/\.(php|phtml|phar|inc)$/i', $path);
        if ($isPhp && config('guard.hash_php_files')) return true;
        if (config('guard.hash_critical_files') && $this->importantChange($rel)) return true;
        return true;
    }

    private function snapshot(int $siteId, string $path, string $pathHash, string $relative, array $m, ?array $row): string
    {
        $groupCol = DB::quoteIdentifier('group');
        if (!$row) { DB::insert("INSERT INTO file_snapshots (site_id,path,path_hash,relative_path,owner,$groupCol,permissions,size,mtime,ctime,inode,mode,uid,gid,extension,file_category,sha256,first_seen_at,last_seen_at,first_seen_scan_id,last_seen_scan_id,last_changed_scan_id,is_missing,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)", [$siteId,$path,$pathHash,$relative,$m['owner'],$m['group'],$m['permissions'],$m['size'],$m['mtime'],$m['ctime'],$m['inode'],$m['mode'],$m['uid'],$m['gid'],$m['extension'],$m['file_category'],$m['sha256'],now(),now(),$GLOBALS['__guard_scan_run_id'] ?? null,$GLOBALS['__guard_scan_run_id'] ?? null,$GLOBALS['__guard_scan_run_id'] ?? null,now(),now()]); return 'new'; }
        $changed = !$this->metadataUnchanged($row, $m);
        $sha = $m['sha256'] ?? $row['sha256'] ?? null;
        DB::statement("UPDATE file_snapshots SET site_id=?,path_hash=?,relative_path=?,owner=?,$groupCol=?,permissions=?,size=?,mtime=?,ctime=?,inode=?,mode=?,uid=?,gid=?,extension=?,file_category=?,sha256=?,last_seen_at=?,last_seen_scan_id=?,last_changed_scan_id=CASE WHEN ? THEN ? ELSE last_changed_scan_id END,last_changed_at=CASE WHEN ? THEN ? ELSE last_changed_at END,is_missing=0,updated_at=? WHERE id=?", [$siteId,$pathHash,$relative,$m['owner'],$m['group'],$m['permissions'],$m['size'],$m['mtime'],$m['ctime'],$m['inode'],$m['mode'],$m['uid'],$m['gid'],$m['extension'],$m['file_category'],$sha,now(),$GLOBALS['__guard_scan_run_id'] ?? null,$changed?1:0,$GLOBALS['__guard_scan_run_id'] ?? null,$changed?1:0,now(),now(),$row['id']]);
        return $changed ? 'changed' : 'same';
    }


    private function buildSiteManifest(string $root, array $options): array
    {
        $root = rtrim(realpath($root) ?: $root, '/');
        $entries = $this->findManifestEntries($root, $options);
        if ($entries === null) $entries = $this->phpManifestEntries($root, $options);
        usort($entries, fn($a,$b) => [$a['relative_path'],$a['type']] <=> [$b['relative_path'],$b['type']]);
        $fileLines=[]; $dirLines=[]; $metaLines=[];
        foreach ($entries as $e) {
            $line = implode("\t", [$e['relative_path'],$e['type'],$e['size'],$e['mtime'],$e['ctime'],$e['mode'],$e['uid'],$e['gid'],$e['extension'],$e['file_category']]);
            if ($e['type'] === 'directory') $dirLines[] = $line; else $fileLines[] = $line;
            $metaLines[] = $line;
        }
        return ['entries'=>$entries, 'site_manifest_hash'=>hash('sha256', implode("\n", $metaLines)), 'file_list_hash'=>hash('sha256', implode("\n", array_map(fn($e)=>$e['relative_path'], array_filter($entries, fn($e)=>$e['type']==='file')))), 'directory_list_hash'=>hash('sha256', implode("\n", array_map(fn($e)=>$e['relative_path'], array_filter($entries, fn($e)=>$e['type']==='directory')))), 'metadata_hash'=>hash('sha256', implode("\n", $metaLines))];
    }

    private function findManifestEntries(string $root, array $options): ?array
    {
        if (!$this->commandExists('find')) return null;
        $cmd = ['find', $root, '-xdev'];
        $prunes = $this->findPruneExpressions($root, $options);
        foreach ($prunes as $i => $path) { if ($i === 0) $cmd[]='('; else $cmd[]='-o'; array_push($cmd, '-path', $path); }
        if ($prunes) array_push($cmd, ')', '-prune', '-o');
        array_push($cmd, '-printf', '%y\t%p\t%s\t%T@\t%C@\t%m\t%U\t%G\n');
        $descriptors = [1=>['pipe','w'], 2=>['pipe','w']]; $proc = @proc_open($cmd, $descriptors, $pipes);
        if (!is_resource($proc)) return null;
        $out = stream_get_contents($pipes[1]); fclose($pipes[1]); if (isset($pipes[2])) fclose($pipes[2]);
        $code = proc_close($proc); if ($code !== 0) return null;
        $entries=[];
        foreach (explode("\n", trim($out)) as $line) {
            if ($line === '') continue; $p = explode("\t", $line); if (count($p) < 8) continue;
            [$y,$path,$size,$mtime,$ctime,$mode,$uid,$gid] = $p; if ($path === $root) continue;
            if ($y !== 'f' && $y !== 'd') continue;
            $rel = ltrim(substr($path, strlen($root)), '/'); if ($rel === '' || $this->isVolatileScannerPath($path, $root, $rel)) continue;
            $type = $y === 'd' ? 'directory' : 'file'; $ext = $type === 'file' ? strtolower(pathinfo($path, PATHINFO_EXTENSION)) : '';
            $cat = $type === 'file' ? $this->fileCategory($path, $rel) : 'directory';
            $entries[] = ['path'=>$path,'relative_path'=>$rel,'path_hash'=>hash('sha256',$path),'type'=>$type,'size'=>(int)$size,'mtime'=>gmdate('Y-m-d H:i:s',(int)floor((float)$mtime)),'ctime'=>gmdate('Y-m-d H:i:s',(int)floor((float)$ctime)),'mode'=>(string)$mode,'uid'=>(string)$uid,'gid'=>(string)$gid,'extension'=>$ext,'file_category'=>$cat];
        }
        return $entries;
    }

    private function phpManifestEntries(string $root, array $options): array
    {
        $entries=[]; $it = new RecursiveIteratorIterator($this->filteredIterator($root, $options), RecursiveIteratorIterator::SELF_FIRST);
        foreach ($it as $file) {
            if ($file->isLink()) continue; $path=$file->getPathname(); $rel=ltrim(substr($path, strlen($root)), '/'); if ($rel==='' || $this->isVolatileScannerPath($path, $root, $rel)) continue;
            $st=@stat($path) ?: []; $type=$file->isDir()?'directory':'file'; if ($type !== 'directory' && !$file->isFile()) continue;
            $entries[]=['path'=>$path,'relative_path'=>$rel,'path_hash'=>hash('sha256',$path),'type'=>$type,'size'=>$type==='file'?($file->getSize()?:0):0,'mtime'=>gmdate('Y-m-d H:i:s',(int)($st['mtime']??0)),'ctime'=>gmdate('Y-m-d H:i:s',(int)($st['ctime']??0)),'mode'=>(string)($st['mode']??''),'uid'=>(string)($st['uid']??''),'gid'=>(string)($st['gid']??''),'extension'=>$type==='file'?strtolower(pathinfo($path, PATHINFO_EXTENSION)):'','file_category'=>$type==='file'?$this->fileCategory($path,$rel):'directory'];
        }
        return $entries;
    }

    private function findPruneExpressions(string $root, array $options): array
    {
        $root = rtrim($root, '/');
        $p = ['/cache/*','/tmp/*','/temp/*','/storage/cache/*','/node_modules/*','/vendor/*','/.jura-*/*','/quarantine/*','/evidence/*'];
        if (!($options['include_old'] ?? config('guard.scan_old_dubl_by_default'))) array_push($p, '/OLD/*','/old.*/*','/DUBL*/*','/dubl*/*');
        if (!($options['include_backups'] ?? false)) array_push($p, '/*backup*/*','/*bak*/*');
        return array_values(array_unique(array_map(fn($x) => $root.$x, $p)));
    }
    private function commandExists(string $cmd): bool { $r = trim((string)@shell_exec('command -v '.escapeshellarg($cmd).' 2>/dev/null')); return $r !== ''; }
    private function isVolatileScannerPath(string $path, string $root, string $rel): bool { return (bool)preg_match('#(^|/)(\.jura[^/]*|quarantine|evidence)(/|$)#i', $rel) || str_starts_with($path, rtrim((string)config('guard.quarantine_path'), '/').'/'); }

    private function previousCompletedManifest(int $siteId): ?array { foreach (DB::select("SELECT site_manifest_hash,file_list_hash,directory_list_hash,metadata_hash,diff_summary FROM scan_runs WHERE status IN ('completed','completed_with_limit') AND site_manifest_hash IS NOT NULL ORDER BY id DESC LIMIT 25") as $r) { $j=json_decode((string)($r['diff_summary'] ?? ''), true) ?: []; $j = array_merge($j, ['site_manifest_hash'=>$r['site_manifest_hash'] ?? null, 'file_list_hash'=>$r['file_list_hash'] ?? null, 'directory_list_hash'=>$r['directory_list_hash'] ?? null, 'metadata_hash'=>$r['metadata_hash'] ?? null]); if (!empty($j['site_manifest_hash'])) return $j; } return null; }
    private function writeManifestSummary(int $runId, int $siteId, array $manifest, array $extra=[]): void { $summary = json_encode(array_merge($this->diffStats, ['site_id'=>$siteId,'site_manifest_hash'=>$manifest['site_manifest_hash'],'file_list_hash'=>$manifest['file_list_hash'],'directory_list_hash'=>$manifest['directory_list_hash'],'metadata_hash'=>$manifest['metadata_hash']], $extra), JSON_UNESCAPED_SLASHES); DB::statement('UPDATE scan_runs SET site_manifest_hash=?,file_list_hash=?,directory_list_hash=?,metadata_hash=?,diff_summary=? WHERE id=?', [$manifest['site_manifest_hash'],$manifest['file_list_hash'],$manifest['directory_list_hash'],$manifest['metadata_hash'],$summary,$runId]); }
    private function loadSnapshotMap(int $siteId): array { $rows=DB::select('SELECT * FROM file_snapshots WHERE site_id=? AND is_missing=0', [$siteId]); $m=[]; foreach($rows as $r) $m[$r['path_hash']]=$r; return $m; }
    private function snapshotMapNeedsMetadataBaseline(array $rows): bool { foreach ($rows as $r) { foreach (['ctime','mode','uid','gid','extension','file_category'] as $k) if (($r[$k] ?? null) === null || (string)($r[$k] ?? '') === '') return true; if ((int)($r['mode'] ?? 0) > 7777) return true; } return false; }
    private function manifestMetadataUnchanged(array $row, array $e): bool { foreach (['size','mtime','ctime','mode','uid','gid','extension','file_category'] as $k) if ((string)($row[$k] ?? '') !== (string)($e[$k] ?? '')) return false; return true; }
    private function metaFromManifestEntry(array $e, ?array $previous=null): array { return ['size'=>$e['size'],'mtime'=>$e['mtime'],'ctime'=>$e['ctime'],'inode'=>$previous['inode']??null,'mode'=>$e['mode'],'uid'=>$e['uid'],'gid'=>$e['gid'],'extension'=>$e['extension'],'file_category'=>$e['file_category'],'sha256'=>$previous['sha256']??null,'owner'=>$e['uid'],'group'=>$e['gid'],'permissions'=>$e['mode']]; }
    private function loadHighRiskFindingPathHashes(): array { $h=[]; foreach (DB::select("SELECT DISTINCT path_hash FROM findings WHERE risk IN ('critical','high') AND status NOT IN ('ignored','quarantined','resolved')") as $r) $h[$r['path_hash']]=true; return $h; }
    private function loadActiveFindingPathHashes(): array { $h=[]; foreach (DB::select("SELECT DISTINCT path_hash FROM findings WHERE status NOT IN ('ignored','quarantined')") as $r) $h[$r['path_hash']]=true; return $h; }
    private function changedOnlyForcedHashes(string $root, array $options): array { $h = $this->highRiskFindingPathHashes ??= $this->loadHighRiskFindingPathHashes(); foreach ((array)($options['force_paths'] ?? []) as $p) $h[hash('sha256',$p)]=true; return $h; }
    private function refreshSnapshotsFromManifest(int $siteId, int $runId, array $files, array $previousRows, array $currentByPathHash, array $deleted): void { foreach ($files as $e) { $prev=$previousRows[$e['path_hash']]??null; $m=$this->metaFromManifestEntry($e,$prev); $this->snapshot($siteId,$e['path'],$e['path_hash'],$e['relative_path'],$m,$prev); } foreach ($deleted as $r) DB::statement('UPDATE file_snapshots SET is_missing=1,last_changed_at=?,last_changed_scan_id=?,updated_at=? WHERE id=?', [now(),$runId,now(),$r['id']]); }


    private function deadlineAt(array $options): ?int { $max = (int)($options['max_seconds'] ?? 0); return $max > 0 ? time() + $max : null; }
    private function deadlineReached(array $options): bool { return !empty($options['deadline_at']) && time() >= (int)$options['deadline_at']; }
    private function mustAnalyzeChangedOnly(string $path, string $root, string $rel, array $options = []): bool { if (!empty($options['force_paths']) && in_array($path, (array)$options['force_paths'], true)) return true; if ($this->newStructuralSuspiciousPath($path)) return true; return isset(($this->highRiskFindingPathHashes ??= $this->loadHighRiskFindingPathHashes())[hash('sha256',$path)]); }
    private function paranoidRecheckCandidate(string $path, string $rel): bool { return $this->isValidationPath($path) || $this->isRootCriticalFile($rel) || $this->isWebConfig($path) || $this->highRiskPath($path); }
    private function metadataUnchanged(array $row, array $m): bool { foreach (['size','mtime','ctime','mode','uid','gid'] as $k) if ((string)($row[$k] ?? '') !== (string)($m[$k] ?? '')) return false; if (!empty($row['inode']) && !empty($m['inode']) && (string)$row['inode'] !== (string)$m['inode']) return false; return true; }
    private function scanMode(array $options): string { $profile=$this->profile($options); if (!empty($options['full_rescan'])) return 'full'; if (!empty($options['changed_only'])) return 'changed_only'; if (!empty($options['diff'])) return 'differential'; return $profile === 'deep' ? 'full' : 'differential'; }
    private function previousRunId(string $scopeType, ?string $scopeValue): ?int { $sql = $scopeValue === null ? "SELECT id FROM scan_runs WHERE status IN ('completed','completed_with_limit') AND scope_type=? AND scope_value IS NULL ORDER BY id DESC LIMIT 1" : "SELECT id FROM scan_runs WHERE status IN ('completed','completed_with_limit') AND scope_type=? AND scope_value=? ORDER BY id DESC LIMIT 1"; $params = $scopeValue === null ? [$scopeType] : [$scopeType,$scopeValue]; $r=DB::first($sql, $params); return $r ? (int)$r['id'] : null; }
    private function accountDiff(string $change): void { $this->diffStats['files_seen_total']++; if ($change==='new') { $this->diffStats['files_new']++; $this->diffStats['files_changed_total']++; } elseif ($change==='changed') { $this->diffStats['files_modified']++; $this->diffStats['files_changed_total']++; } }
    private function fileCategory(string $path, string $rel): string { if ($this->isPhpLike($path)) return 'php'; if ($this->isWebConfig($path)) return 'config'; if ($this->isOrdinaryMedia($path)) return 'media'; return strtolower(pathinfo($path, PATHINFO_EXTENSION) ?: 'other'); }
    private function heavyAnalysisCandidate(string $path, string $root, string $rel, array $m): bool { $base=basename($path); if ($this->isWebConfig($path) || preg_match('/^google.*\.html$/i',$base) || str_starts_with($base,'.')) return true; if ($this->suspiciousLocation($path) || $this->isValidationPath($path)) return true; if ($this->isPhpLike($path) && preg_match('#/(uploads|cache|tmp|media|images|storage)/#i',$path)) return true; if (preg_match('/\.(phar|phtml|shtml|cgi|pl|py|sh|asp|aspx)$/i',$path)) return true; if (isset(($this->activeFindingPathHashes ??= $this->loadActiveFindingPathHashes())[hash('sha256',$path)])) return true; return $this->structuralSuspiciousPath($path); }
    private function highRiskPath(string $path): bool { return (bool)preg_match('#/(wp-admin|wp-content|wp-includes|uploads|cache|tmp|media|images|storage)(/|$)#i', $path); }
    private function structuralSuspiciousPath(string $path): bool { return $this->newStructuralSuspiciousPath($path); }
    private function newStructuralSuspiciousPath(string $path): bool { return (bool)preg_match('#/(404SBG|configCWE|FSS-NPY)(/|$)|/\.txt404(/|$)|/(accesshash|admin-env)(/|$)|/(WHMCS|Joomla|Drupal|OpenCart|PrestaShop)/(?:404SBG|\.txt404|env|accesshash|admin-env)(/|$)#i', $path); }

    private function detect(array $site, string $path, string $relative, array $m, string $change, array $options = []): array
    {
        $out = []; $isPhp = $this->isPhpLike($path); $explicitlyAllowed = $this->rules->isAllowed($path, $m['sha256']);
        if ($this->newStructuralSuspiciousPath($path)) $out[] = ['risk'=>'critical','type'=>'malicious_structure','rule_key'=>'structural-malicious-directory','title'=>'Suspicious malicious directory structure','description'=>'Path matches known fake CMS/env/404SBG/configCWE/FSS-NPY structure used by nested loaders.','matched'=>[['name'=>'structural-path','risk'=>'critical','pattern'=>'fake CMS/env loader directory','snippet'=>$relative]], 'log_ids'=>[]];
        $content = ($isPhp || $this->isWebConfig($path) || $this->isValidationPath($path) || $this->isSeoScannable($path)) ? @file_get_contents($path, false, null, 0, config('guard.max_file_read_bytes')) ?: '' : '';
        $loaderEvidence = $this->selfReadingPackedLoaderEvidence($content);
        $allowed = $explicitlyAllowed || ($this->knownFalsePositivePath($path) && !$loaderEvidence);
        $logIds = $this->relatedLogEventIds($path);

        $engine = new SignatureEngine();
        foreach ($engine->enabledSignatures() as $sig) {
            $match = $engine->match($sig, $path, $relative, $m, $content, $site['path'] ?? '');
            if ($match) {
                $s = $match['signature'];
                $this->recordSignatureHit($s, $options ?? []);
                $out[] = ['risk'=>$s['risk'] ?? 'high','type'=>$s['type'] ?? 'signature','rule_key'=>'signature:'.($s['slug'] ?? $s['name']),'title'=>'Matched signature: '.($s['name'] ?? 'unknown'),'description'=>$match['risk_explanation'],'matched'=>$match['matched'],'log_ids'=>$logIds,'signature'=>$s];
            }
        }
        if ($dle = $this->dleStructuralFinding($site, $path, $relative, $content)) $out[] = $dle;
        if ($this->isValidationPath($path) && ($isPhp || $this->isWebConfig($path))) {
            $risk = $allowed ? 'low' : ($this->fakeWellKnownPath($path) || $isPhp ? 'critical' : 'high');
            $out[] = ['risk'=>$risk,'type'=>'validation_path_malware','rule_key'=>'validation-path-executable','title'=>'Executable or config file under validation directory','description'=>($this->fakeWellKnownPath($path)?'Fake well-known directory without leading dot is suspicious. ':'').'Validation/ACME paths should not contain PHP loaders or dangerous handlers.','matched'=>[], 'log_ids'=>$logIds];
        }

        if ($seo = $this->seoDoorwayEvidence($path, $relative, $content, $change)) {
            $risk = $allowed ? 'low' : $seo['risk'];
            $out[] = ['risk'=>$risk,'type'=>'seo_spam','rule_key'=>$seo['rule_key'],'title'=>$seo['title'],'description'=>$seo['description'],'matched'=>$seo['matched'], 'log_ids'=>$logIds];
        }
        if ($loaderEvidence) $out[] = ['risk'=>$allowed?'low':'critical','type'=>'packed_loader','rule_key'=>'self-reading-packed-loader','title'=>'Self-reading packed PHP loader','description'=>'Detected eval with gzuncompress/gzinflate, self-reading file_get_contents(__FILE__), and a negative substr offset or appended binary/compressed payload.','matched'=>[$loaderEvidence], 'log_ids'=>$logIds];
        $matched = [];
        foreach ($this->rules->enabledRules() as $r) {
            $hit = match ($r['pattern_type']) { 'regex' => (bool)@preg_match($r['pattern'], $path), 'path' => fnmatch($r['pattern'], $path, FNM_CASEFOLD) || fnmatch($r['pattern'], basename($path), FNM_CASEFOLD), default => $isPhp && stripos($content, $r['pattern']) !== false };
            if ($hit) $matched[] = $r;
        }
        $fnHits = array_values(array_filter($matched, fn($r)=>$r['type']==='suspicious_php'));
        $badHits = array_values(array_filter($matched, fn($r)=>$r['type']==='webshell'));
        $nameOnly = $fnHits && !$badHits && !$this->suspiciousContent($content) && !$this->suspiciousLocation($path) && !$this->malwareLikeName($path);
        if ($badHits || count($fnHits) >= 2 || ($fnHits && ($this->suspiciousLocation($path) || $this->malwareLikeName($path)))) {
            $risk = $allowed ? 'low' : ($nameOnly ? 'medium' : $this->maxRisk($matched));
            if ($logIds && !$allowed) $risk = $this->raiseRisk($risk);
            $out[] = ['risk'=>$risk, 'type'=>$badHits?'webshell':'suspicious_php', 'rule_key'=>'malware-indicators', 'title'=>$allowed?'Allowlisted suspicious file changed':'Suspicious PHP malware indicators', 'description'=>'Matched combined Jura AV Monitor rules.', 'matched'=>$matched, 'log_ids'=>$logIds];
        }
        if ($isPhp && is_writable($path) && $this->suspiciousLocation($path)) $out[] = ['risk'=>$allowed?'low':'medium','type'=>'writable_php','rule_key'=>'writable-risky-php','title'=>'Writable PHP in risky directory','description'=>'PHP file is writable inside upload/cache/temp-like path.','matched'=>[], 'log_ids'=>$logIds];
        if ($change === 'changed' && $this->importantChange($relative)) $out[] = ['risk'=>$allowed?'low':'low','type'=>'cms_integrity','rule_key'=>'important-change','title'=>'CMS/core integrity changed (needs baseline)','description'=>'Core_change is grouped as an integrity warning and needs a trusted baseline before being treated as malware.','matched'=>[], 'log_ids'=>$logIds];
        return $out;
    }


    private function recordSignatureHit(array $sig, array $options): void
    {
        $key = (string)($sig['slug'] ?? $sig['name'] ?? 'unknown');
        $this->signatureHitCounts[$key] = ($this->signatureHitCounts[$key] ?? 0) + 1;
        $limit = (int)($options['noisy_signature_threshold'] ?? 100);
        if ($this->signatureHitCounts[$key] === $limit + 1) {
            $this->noisySignatures[$key] = ['signature'=>$key, 'name'=>$sig['name'] ?? $key, 'matches'=>$this->signatureHitCounts[$key], 'warning'=>'Signature matched more than threshold in one scan; review for noisy false positives.'];
            $this->progress($options, "Noisy signature warning: {$key} matched more than {$limit} files");
        } elseif (isset($this->noisySignatures[$key])) {
            $this->noisySignatures[$key]['matches'] = $this->signatureHitCounts[$key];
        }
        if (!empty($options['verbose'])) $this->progress($options, 'Matched signature '.$key);
    }

    private function dleStructuralFinding(array $site, string $path, string $relative, string $content): ?array
    {
        if (($site['cms_type'] ?? '') !== 'dle') return null;
        $rel = str_replace('\\', '/', ltrim($relative, '/'));
        $base = basename($rel);
        $risk = 'high'; $reason = null;
        if (preg_match('#^(wp-blog-header\.php|wp-load\.php|wp-login\.php|xmlrpc\.php)$#i', $rel) || preg_match('#^(wp-admin|wp-content|wp-includes)(/|$)#i', $rel)) $reason = 'Fake WordPress artefact present in DataLife Engine root';
        elseif (preg_match('#^uploads/.+\.(php|phtml|phar|php[578]?|inc)$#i', $rel)) $reason = 'Executable PHP file inside DLE uploads';
        elseif (preg_match('#/(engine/cache|engine/data|uploads|templates)/#i', '/'.$rel) && ($this->malwareLikeName($path) || $this->suspiciousContent($content))) $reason = 'Shell-like file under DLE writable/cache/data/template path';
        elseif (str_starts_with($base, '.') && $this->isPhpLike($path)) $reason = 'Hidden PHP file inside DLE site';
        elseif ($this->isWebConfig($path) && preg_match('/AddHandler|SetHandler|php_value|auto_prepend_file|AddType/i', $content)) $reason = 'Suspicious .htaccess/PHP handler directive in DLE site';
        elseif (preg_match('#^(wordpress|wp|joomla|opencart|drupal|bitrix)/#i', $rel)) $reason = 'Nested fake/duplicate CMS directory inside DLE site';
        elseif (preg_match('#^[^/]+\.php$#i', $rel) && !preg_match('#^(index|admin|cron|upgrade|api|engine)\.php$#i', $rel)) { $reason = 'Unexpected root PHP file in DLE site'; $risk = 'medium'; }
        if (!$reason) return null;
        if (preg_match('/eval\s*\(|base64_decode\s*\(|gz(inflate|uncompress)\s*\(|file_get_contents\s*\(\s*__FILE__/i', $content)) $risk = 'critical';
        return ['risk'=>$risk,'type'=>'cms_structure','rule_key'=>'dle-structural-warning','title'=>'DataLife Engine structural warning','description'=>$reason,'matched'=>[['name'=>'dle-structure','risk'=>$risk,'pattern'=>$reason,'snippet'=>$rel]], 'log_ids'=>$this->relatedLogEventIds($path)];
    }

    private function isSeoScannable(string $path): bool { return (bool)preg_match('/\.(php|html?|txt)$/i', $path); }
    private function seoDoorwayEvidence(string $path, string $relative, string $content, string $change): ?array
    {
        $rootDepth = substr_count(trim($relative, '/'), '/');
        $name = basename($path);
        if (preg_match('/^google[a-z0-9_-]*\.html$/i', $name) && $rootDepth === 0) {
            return ['risk'=>$change === 'new' ? 'high' : 'medium','rule_key'=>'suspicious-google-verification','title'=>'Suspicious Google site verification file','description'=>'Suspicious Google Search Console verification file added or present in web root. Verify ownership change with the site owner.','matched'=>[['name'=>'google-verification-root','risk'=>'high','pattern'=>'google*.html in web root','snippet'=>$name]]];
        }
        if ($content === '' || !$this->isSeoScannable($path)) return null;
        $hay = strtolower($content.' '.$relative);
        $kw = ['paris88','situs gacor','mahjong wins','rupiah','judi','slot','taruhan','gacor','daftar','login'];
        $kwHits = array_values(array_filter($kw, fn($k)=>str_contains($hay, $k)));
        $extHits = [];
        if (preg_match_all('#https?://([^/"\'<>\s]+)#i', $content, $m)) {
            foreach ($m[1] as $host) if (preg_match('/(pages\.dev|casino|slot|judi|gacor|paris88|mahjong|cloudflare)/i', $host)) $extHits[] = $host;
        }
        $seoDir = (bool)preg_match('#(^|/)(denza|casino|slot|mahjong)(/|$)#i', $relative);
        $staticPhp = (bool)preg_match('/\.php$/i', $path) && strlen($content) > 2000 && substr_count($content, '<?php') <= 1 && preg_match('/<html|<head|<body|rel=["\'](?:amphtml|canonical|alternate)/i', $content);
        $googleInside = str_contains($hay, 'google-site-verification');
        $score = count($kwHits) + count(array_unique($extHits)) + ($seoDir ? 2 : 0) + ($staticPhp ? 2 : 0) + ($googleInside ? 1 : 0);
        if ($score < 3 || count($kwHits) < 2) return null;
        $risk = $score >= 7 ? 'critical' : 'high';
        $matches = [];
        foreach ($kwHits as $k) $matches[] = ['name'=>'gambling-keyword','risk'=>$risk,'pattern'=>$k,'snippet'=>$k];
        foreach (array_unique($extHits) as $h) $matches[] = ['name'=>'suspicious-external-seo-link','risk'=>$risk,'pattern'=>$h,'snippet'=>$h];
        if ($seoDir) $matches[] = ['name'=>'seo-looking-directory','risk'=>'high','pattern'=>'new/suspicious SEO directory','snippet'=>$relative];
        if ($staticPhp) $matches[] = ['name'=>'static-html-in-php','risk'=>'high','pattern'=>'large static HTML content inside PHP file','snippet'=>basename($path)];
        return ['risk'=>$risk,'rule_key'=>'seo-doorway-gambling-spam','title'=>'SEO doorway / gambling spam page','description'=>'Static doorway content with gambling keywords and suspicious external SEO links/domains was detected.','matched'=>$matches];
    }
    private static ?array $defaultRulesCache = null;
    private function defaultRulesConfig(): array { return self::$defaultRulesCache ??= require base_path('rules/default-rules.php'); }
    private function knownFalsePositivePath(string $path): bool { foreach ($this->defaultRulesConfig()['allowlist'] as $p) if (fnmatch($p, $path, FNM_CASEFOLD)) return true; return false; }
    private function selfReadingPackedLoaderEvidence(string $content): ?array
    {
        if ($content === '') return null;
        $code = $this->phpWithoutComments($content);
        $normalized = strtolower($this->normalizeConcatenatedStrings($code));
        $compact = preg_replace('/\s+/', '', $normalized);

        $eval = (bool)preg_match('/\beval\s*\(/i', $normalized);
        $gzAliases = $this->functionAliases($normalized, ['gzuncompress', 'gzinflate']);
        $fileAliases = $this->functionAliases($normalized, ['file_get_contents']);
        $gz = (bool)preg_match('/\b(?:gzuncompress|gzinflate)\s*\(/i', $normalized) || (bool)preg_match('/\(?\s*[\'\"](?:gzuncompress|gzinflate)[\'\"]\s*\)?\s*\(/i', $normalized) || $this->hasVariableFunctionCall($normalized, $gzAliases);
        $selfRead = str_contains($compact, 'file_get_contents(__file__)') || (bool)preg_match('/\(?\s*[\'\"]file_get_contents[\'\"]\s*\)?\s*\(\s*__file__\s*\)/i', $normalized);
        foreach ($fileAliases as $alias) {
            if (preg_match('/\$' . preg_quote($alias, '/') . '\s*\(\s*__file__\s*\)/i', $normalized)) { $selfRead = true; break; }
        }
        $negativeSubstr = (bool)preg_match('/\bsubstr\s*\([^;]*,\s*-\d+/is', $normalized);
        $appendedPayload = $this->hasAppendedCompressedPayload($content);

        $indicators = [
            'eval' => $eval,
            'compressed_decoder' => $gz,
            'self_reading_file_get_contents___FILE__' => $selfRead,
            'negative_substr_offset' => $negativeSubstr,
            'appended_binary_or_compressed_payload' => $appendedPayload,
        ];
        if (!$eval || !$gz || !$selfRead || (!$negativeSubstr && !$appendedPayload)) return null;

        return [
            'name' => 'self-reading-packed-loader',
            'risk' => 'critical',
            'pattern' => 'eval + gzuncompress/gzinflate + file_get_contents(__FILE__) + negative substr offset or appended binary/compressed payload',
            'snippet' => $this->matchedSnippet($code),
            'why' => 'Strong self-reading packed loader indicators were present together; standalone eval, gzip helpers, file_get_contents, and substr are not enough.',
            'indicators' => $indicators,
        ];
    }

    private function phpWithoutComments(string $content): string
    {
        if (!str_contains($content, '<?')) $content = "<?php\n" . $content;
        $out = '';
        foreach (@token_get_all($content) ?: [] as $token) {
            if (is_array($token)) {
                if (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) continue;
                $out .= $token[1];
            } else {
                $out .= $token;
            }
        }
        return $out;
    }

    private function normalizeConcatenatedStrings(string $code): string
    {
        $previous = null;
        while ($previous !== $code) {
            $previous = $code;
            $code = preg_replace_callback('/([\'\"])([^\'\"]*)\1\s*\.\s*([\'\"])([^\'\"]*)\3/s', fn($m) => $m[1] . $m[2] . $m[4] . $m[1], $code) ?? $code;
        }
        return $code;
    }

    private function functionAliases(string $code, array $functions): array
    {
        $aliases = [];
        $quoted = implode('|', array_map(fn($f) => preg_quote($f, '/'), $functions));
        if (preg_match_all('/\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*[\'\"](' . $quoted . ')[\'\"]/i', $code, $matches)) {
            foreach ($matches[1] as $alias) $aliases[] = strtolower($alias);
        }
        return array_values(array_unique($aliases));
    }

    private function hasVariableFunctionCall(string $code, array $aliases): bool
    {
        foreach ($aliases as $alias) if (preg_match('/\$' . preg_quote($alias, '/') . '\s*\(/i', $code)) return true;
        return false;
    }

    private function hasAppendedCompressedPayload(string $content): bool
    {
        $pos = strrpos($content, '?>');
        if ($pos === false) return false;
        $tail = substr($content, $pos + 2);
        if (trim($tail) === '') return false;
        return (bool)preg_match('/[\x00-\x08\x0E-\x1F\x7F-\xFF]/', $tail);
    }

    private function matchedSnippet(string $code): string
    {
        $pos = stripos($code, 'eval');
        if ($pos === false) $pos = 0;
        $snippet = substr($code, max(0, $pos - 160), 420);
        $snippet = preg_replace('/[\x00-\x08\x0E-\x1F\x7F-\xFF]/', '.', $snippet) ?? $snippet;
        return trim($snippet);
    }
    private function suspiciousContent(string $content): bool { return (bool)preg_match('/(eval\s*\(|assert\s*\(|gzinflate\s*\(|base64_decode\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\()/i', $content); }
    private function malwareLikeName(string $path): bool { return (bool)preg_match('/\/(gallery888|zebra|mah|compat-kuro|AuthControlIer|access\.policy|session\.manage|field\.api|[a-f0-9]{12,})\.php$/i', $path); }
    private function suspiciousLocation(string $path): bool { foreach ($this->defaultRulesConfig()['suspicious_paths'] as $p) if (fnmatch($p, $path, FNM_CASEFOLD)) return true; return false; }
    private function criticalChange(string $rel): bool { foreach ($this->defaultRulesConfig()['critical_changes'] as $p) if (fnmatch($p, $rel, FNM_CASEFOLD)) return true; return false; }
    private function importantChange(string $rel): bool { $r=$this->defaultRulesConfig(); foreach (array_merge($r['critical_changes'],$r['important_changes']) as $p) if (fnmatch($p, $rel, FNM_CASEFOLD)) return true; return false; }
    private function maxRisk(array $rules): string { $order=['low'=>1,'medium'=>2,'high'=>3,'critical'=>4]; $risk='low'; foreach($rules as $r) if(($order[$r['risk']]??0)>($order[$risk]??0)) $risk=$r['risk']; return $risk; }
    private function raiseRisk(string $risk): string { return ['low'=>'medium','medium'=>'high','high'=>'critical','critical'=>'critical'][$risk] ?? 'high'; }
    private function relatedLogEventIds(string $path): array { $base = basename($path); if (!$base) return []; return array_map(fn($r)=>(int)$r['id'], DB::select("SELECT id FROM log_events WHERE uri LIKE ? AND NOT (LOWER(uri) LIKE '%delivery.png%' OR LOWER(uri) IN ('/delivery','/ua/delivery','/ru/delivery')) ORDER BY id DESC LIMIT 20", ['%'.$base.'%'])); }

    private function upsertFinding(int $runId, int $siteId, string $path, array $m, array $f): void
    {
        $rules = json_encode(array_map(fn($r)=>array_filter(['name'=>$r['name']??'runtime','risk'=>$r['risk']??$f['risk'],'pattern'=>$r['pattern']??'','snippet'=>$r['snippet']??null,'why'=>$r['why']??null,'indicators'=>$r['indicators']??null], fn($v)=>$v !== null), $f['matched']), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        $sig = $f['signature'] ?? null;
        $sigId = isset($sig['id']) && $sig['id'] !== '' ? (int)$sig['id'] : null;
        $sigName = $sig['name'] ?? null;
        $sigSource = $sig['source'] ?? null;
        $matchDetails = json_encode(['signature'=>$sigName,'signature_id'=>$sigId,'source'=>$sigSource,'matched'=>$f['matched'] ?? [],'risk_explanation'=>$f['description'] ?? null], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        $pathHash = hash('sha256', $path);
        $fingerprint = hash('sha256', $path.'|'.$f['type'].'|'.($f['rule_key'] ?? '').'|'.($m['sha256'] ?? ''));
        $findingHash = hash('sha256', $path.'|'.$f['type'].'|'.($f['rule_key'] ?? '').'|'.$fingerprint);
        $ignored = DB::first("SELECT id,sha256 FROM findings WHERE finding_hash=? AND path_hash=? AND path=? AND status='ignored'", [$findingHash,$pathHash,$path]);
        if ($ignored && ($ignored['sha256'] ?? null) === ($m['sha256'] ?? null)) {
            $this->recordScanFinding($runId, (int)$ignored['id']);
            return;
        }
        $row = DB::first("SELECT id,status FROM findings WHERE finding_hash=? AND path_hash=? AND path=? AND status NOT IN ('ignored','quarantined')", [$findingHash,$pathHash,$path]);
        $logIds = json_encode($f['log_ids'] ?? [], JSON_UNESCAPED_SLASHES);
        if ($row) {
            $findingId = (int)$row['id'];
            DB::statement('UPDATE findings SET site_id=?,path_hash=?,finding_hash=?,risk=?,rule_key=?,title=?,description=?,matched_rules=?,related_log_event_ids=?,sha256=?,size=?,mtime=?,owner=?,permissions=?,last_seen_at=?,last_seen_scan_id=?,last_matched_signature_id=?,matched_signature_name=?,matched_signature_source=?,signature_match_details=?,updated_at=? WHERE id=?', [$siteId,$pathHash,$findingHash,$f['risk'],$f['rule_key'] ?? null,$f['title'],$f['description'],$rules,$logIds,$m['sha256'],$m['size'],$m['mtime'],$m['owner'],$m['permissions'],now(),$runId,$sigId,$sigName,$sigSource,$matchDetails,now(),$findingId]);
        } else {
            $findingId = DB::insert('INSERT INTO findings (scan_run_id,first_seen_scan_id,last_seen_scan_id,last_matched_signature_id,matched_signature_name,matched_signature_source,signature_match_details,site_id,path,path_hash,finding_hash,risk,status,type,rule_key,fingerprint,title,description,matched_rules,related_log_event_ids,sha256,size,mtime,owner,permissions,first_seen_at,last_seen_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [$runId,$runId,$runId,$sigId,$sigName,$sigSource,$matchDetails,$siteId,$path,$pathHash,$findingHash,$f['risk'],'new',$f['type'],$f['rule_key'] ?? null,$fingerprint,$f['title'],$f['description'],$rules,$logIds,$m['sha256'],$m['size'],$m['mtime'],$m['owner'],$m['permissions'],now(),now(),now(),now()]);
            $this->maybeAutoCreateSignature($findingId, $path, $f, $m, $sig !== null);
        }
        $this->recordScanFinding($runId, $findingId);
    }

    private function recordScanFinding(int $runId, int $findingId): void
    {
        $verb = DB::driver() === 'mysql' ? 'INSERT IGNORE' : 'INSERT OR IGNORE';
        DB::statement("{$verb} INTO scan_run_findings (scan_run_id,finding_id,observed_at) VALUES (?,?,?)", [$runId,$findingId,now()]);
    }

    private function maybeAutoCreateSignature(int $findingId, string $path, array $f, array $m, bool $alreadyFromSignature): void
    {
        if (!config('guard.auto_signature_on_critical_findings')) return;
        if (($f['risk'] ?? '') !== 'critical') return;
        if ($alreadyFromSignature) return; // already matched a known signature; nothing new to learn
        $sha = $m['sha256'] ?? null;
        if (!$sha || (int)($m['size'] ?? 0) === 0 || strtolower((string)$sha) === hash('sha256', '')) return;
        $slug = 'auto-' . substr($sha, 0, 16);
        if (DB::first('SELECT id FROM malware_signatures WHERE slug=?', [$slug])) return;
        DB::insert('INSERT INTO malware_signatures (name,slug,description,risk,type,pattern_type,pattern_json,target_extensions,enabled,source,source_finding_id,source_file_sha256,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,1,?,?,?,?,?)', [
            'Auto: ' . basename($path),
            $slug,
            'Automatically created from finding #' . $findingId . ' (' . ($f['title'] ?? '') . ') during a scan.',
            'critical',
            $f['type'] ?? 'suspicious_php',
            'hash',
            json_encode(['sha256' => [$sha]], JSON_UNESCAPED_SLASHES),
            '[]',
            'auto_finding',
            $findingId,
            $sha,
            now(),
            now(),
        ]);
    }


    private function shouldRunLogAnalysis(array $options): bool
    {
        if (!empty($options['skip_logs'])) return false;
        if (!empty($options['include_logs'])) return true;
        if ($this->profile($options) === 'deep') return true;
        if ($this->profile($options) === 'fast' || $this->scanMode($options) === 'changed_only') return false;
        return true;
    }

    private function logSkipMessage(array $options): string
    {
        if ($this->profile($options) === 'fast') return 'Skipping log analysis for fast scan';
        if ($this->scanMode($options) === 'changed_only') return 'Skipping log analysis for changed-only scan';
        return 'Skipping log analysis';
    }

    private function detectCmsForSite(array $site): array
    {
        $cms = (new CmsDetector())->detect($site['path']);
        DB::statement('UPDATE sites SET cms_type=?, cms_version=?, cms_detected_at=?, cms_confidence=?, cms_admin_path=?, cms_notes=?, updated_at=? WHERE id=?', [$cms['type'],$cms['version'],now(),$cms['confidence'],$cms['admin_path'],$cms['notes'],now(),$site['id']]);
        return $cms;
    }

    private function progress(array $options, string $message): void
    {
        if (($options['quiet'] ?? false) === true) return;
        echo '['.now().'] '.$message.PHP_EOL;
    }
}
