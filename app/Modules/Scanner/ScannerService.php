<?php
namespace App\Modules\Scanner;

use App\Modules\Inventory\InventoryService;
use App\Modules\LogAnalyzer\LogAnalyzerService;
use App\Modules\Rules\RuleRepository;
use App\Support\DB;
use FilesystemIterator;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Throwable;

class ScannerService
{
    private int $skippedFolders = 0;
    public function __construct(private ?RuleRepository $rules = null) { $this->rules ??= new RuleRepository(); }

    public function scan(string $scopeType = 'full', ?string $scopeValue = null, array $options = []): int
    {
        $runId = DB::insert('INSERT INTO scan_runs (started_at,status,scope_type,scope_value,files_scanned,findings_count,created_at,updated_at) VALUES (?,?,?,?,0,0,?,?)', [now(),'running',$scopeType,$scopeValue,now(),now()]);
        $files = 0; $findings = 0;
        $stop = function (string $signal) use (&$runId, &$files, &$findings): void {
            DB::statement('UPDATE scan_runs SET status=?, finished_at=?, files_scanned=?, findings_count=?, error_text=?, updated_at=? WHERE id=?', ['failed', now(), $files, $findings, $signal, now(), $runId]);
            exit(130);
        };
        if (function_exists('pcntl_async_signals')) {
            pcntl_async_signals(true);
            pcntl_signal(SIGTERM, fn() => $stop('Stopped by SIGTERM'));
            pcntl_signal(SIGINT, fn() => $stop('Stopped by SIGINT'));
        }
        try {
            $inv = new InventoryService();
            $sites = match ($scopeType) { 'user' => $inv->refresh($scopeValue, null, $options), 'site' => $inv->refresh(null, $scopeValue, $options), default => $inv->refresh(null, null, $options) };
            $this->progress($options, sprintf('Scan #%d: %d site(s) selected for %s%s', $runId, count($sites), $scopeType, $scopeValue ? ': '.$scopeValue : ''));
            foreach ($sites as $site) {
                [$f, $c] = $this->scanSite($site, $runId, $options); $files += $f; $findings += $c;
                DB::statement('UPDATE sites SET last_scan_at=?, updated_at=? WHERE id=?', [now(), now(), $site['id']]);
            }
            if (!($options['skip_logs'] ?? false)) (new LogAnalyzerService())->analyze();
            DB::statement('UPDATE scan_runs SET status=?, finished_at=?, files_scanned=?, findings_count=?, updated_at=? WHERE id=?', ['completed', now(), $files, $findings, now(), $runId]);
            $this->progress($options, "Scan #$runId completed: files=$files findings=$findings skipped_folders={$this->skippedFolders}");
            return $runId;
        } catch (Throwable $e) {
            DB::statement('UPDATE scan_runs SET status=?, finished_at=?, files_scanned=?, findings_count=?, error_text=?, updated_at=? WHERE id=?', ['failed', now(), $files, $findings, $e->getMessage(), now(), $runId]);
            throw $e;
        }
    }

    private function scanSite(array $site, int $runId, array $options): array
    {
        $start = time(); $count = 0; $findings = 0; $seen = [];
        $maxFiles = (int)($options['max_files'] ?? config('guard.max_files_per_site'));
        $maxSeconds = (int)($options['max_seconds'] ?? config('guard.max_scan_seconds_per_site'));
        $dryRun = (bool)($options['dry_run'] ?? false);
        $this->progress($options, "Scanning site {$site['name']} ({$site['path']})");
        $it = new RecursiveIteratorIterator($this->filteredIterator($site['path'], $options));
        foreach ($it as $file) {
            if ($maxFiles > 0 && $count >= $maxFiles) { $this->progress($options, "Max files reached for {$site['name']}: $maxFiles"); break; }
            if ($maxSeconds > 0 && time() - $start >= $maxSeconds) { $this->progress($options, "Max seconds reached for {$site['name']}: $maxSeconds"); break; }
            if (!$file->isFile() || $file->isLink()) continue;
            $path = $file->getPathname(); $seen[$path] = true; $count++;
            $relative = ltrim(str_replace($site['path'], '', $path), '/');
            $previous = DB::first('SELECT * FROM file_snapshots WHERE path=?', [$path]);
            $meta = $this->meta($path, $previous, $relative);
            $change = $dryRun ? 'dry-run' : $this->snapshot($site['id'], $path, $relative, $meta, $previous);
            foreach ($this->detect($site, $path, $relative, $meta, $change) as $finding) {
                if (!$dryRun) $this->upsertFinding($runId, $site['id'], $path, $meta, $finding);
                $findings++;
            }
            if ($count % 1000 === 0) $this->progress($options, "Progress {$site['name']}: files=$count findings=$findings elapsed=".(time()-$start).'s');
        }
        if (!$dryRun) foreach (DB::select('SELECT id,path FROM file_snapshots WHERE site_id=? AND is_missing=0', [$site['id']]) as $snap) if (!isset($seen[$snap['path']]) && !file_exists($snap['path'])) DB::statement('UPDATE file_snapshots SET is_missing=1,last_changed_at=?,updated_at=? WHERE id=?', [now(),now(),$snap['id']]);
        $this->progress($options, "Finished {$site['name']}: files=$count findings=$findings skipped_folders={$this->skippedFolders} elapsed=".(time()-$start).'s');
        return [$count, $findings];
    }

    private function filteredIterator(string $root, array $options): RecursiveCallbackFilterIterator
    {
        $dir = new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS);
        return new RecursiveCallbackFilterIterator($dir, function ($current) use ($options) {
            if (!$current->isDir()) return true;
            $path = $current->getPathname(); $name = $current->getFilename();
            $lower = strtolower($name);
            $skip = false;
            if (!($options['include_old'] ?? config('guard.scan_old_dubl_by_default')) && (str_contains($lower, 'old') || str_contains($lower, 'dubl'))) $skip = true;
            if (!($options['include_storage'] ?? config('guard.scan_storage_by_default')) && $lower === 'storage') $skip = true;
            if (!($options['include_backups'] ?? false) && (str_contains($lower, 'backup') || str_contains($lower, 'bak'))) $skip = true;
            foreach (config('guard.exclude_paths') as $pattern) if (fnmatch($pattern, $path.'/', FNM_PATHNAME|FNM_CASEFOLD)) $skip = true;
            if ($skip) { $this->skippedFolders++; return false; }
            return true;
        });
    }

    private function meta(string $path, ?array $previous = null, string $relative = ''): array
    {
        $stat = @stat($path) ?: [];
        $size = @filesize($path) ?: 0;
        $mtime = isset($stat['mtime']) ? gmdate('Y-m-d H:i:s',$stat['mtime']) : null;
        $owner = function_exists('posix_getpwuid') ? (posix_getpwuid($stat['uid'] ?? 0)['name'] ?? (string)($stat['uid'] ?? '')) : (string)($stat['uid'] ?? '');
        $group = function_exists('posix_getgrgid') ? (posix_getgrgid($stat['gid'] ?? 0)['name'] ?? (string)($stat['gid'] ?? '')) : (string)($stat['gid'] ?? '');
        $permissions = substr(sprintf('%o', @fileperms($path)), -4);
        $sha = $previous['sha256'] ?? null;
        if ($this->shouldHash($path, $relative, $size, $previous, $mtime, $permissions, $owner)) $sha = @hash_file('sha256',$path) ?: null;
        return ['size'=>$size, 'mtime'=>$mtime, 'sha256'=>$sha, 'owner'=>$owner, 'group'=>$group, 'permissions'=>$permissions];
    }

    private function shouldHash(string $path, string $rel, int $size, ?array $previous, ?string $mtime, string $permissions, string $owner): bool
    {
        if ($size > ((int)config('guard.max_file_size_for_hash_mb') * 1024 * 1024)) return false;
        if (config('guard.hash_all_files')) return true;
        $isPhp = (bool)preg_match('/\.(php|phtml|phar|inc)$/i', $path);
        if ($isPhp && config('guard.hash_php_files')) return true;
        if (config('guard.hash_critical_files') && $this->importantChange($rel)) return true;
        if (!$previous) return true;
        return (int)$previous['size'] !== $size || (string)$previous['mtime'] !== (string)$mtime || (string)$previous['permissions'] !== $permissions || (string)$previous['owner'] !== $owner;
    }

    private function snapshot(int $siteId, string $path, string $relative, array $m, ?array $row): string
    {
        $groupCol = DB::quoteIdentifier('group');
        if (!$row) { DB::insert("INSERT INTO file_snapshots (site_id,path,relative_path,owner,$groupCol,permissions,size,mtime,sha256,first_seen_at,last_seen_at,is_missing,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,0,?,?)", [$siteId,$path,$relative,$m['owner'],$m['group'],$m['permissions'],$m['size'],$m['mtime'],$m['sha256'],now(),now(),now(),now()]); return 'new'; }
        $changed = ($row['sha256'] !== $m['sha256'] || (string)$row['mtime'] !== (string)$m['mtime'] || (string)$row['permissions'] !== (string)$m['permissions'] || (string)$row['owner'] !== (string)$m['owner'] || (int)$row['size'] !== (int)$m['size']);
        DB::statement("UPDATE file_snapshots SET site_id=?,relative_path=?,owner=?,$groupCol=?,permissions=?,size=?,mtime=?,sha256=?,last_seen_at=?,last_changed_at=CASE WHEN ? THEN ? ELSE last_changed_at END,is_missing=0,updated_at=? WHERE id=?", [$siteId,$relative,$m['owner'],$m['group'],$m['permissions'],$m['size'],$m['mtime'],$m['sha256'],now(),$changed?1:0,now(),now(),$row['id']]);
        return $changed ? 'changed' : 'same';
    }

    private function detect(array $site, string $path, string $relative, array $m, string $change): array
    {
        $out = []; $isPhp = (bool)preg_match('/\.(php|phtml|phar|inc)$/i', $path); $allowed = $this->rules->isAllowed($path, $m['sha256']);
        if ($this->knownFalsePositivePath($path)) $allowed = true;
        $content = $isPhp ? @file_get_contents($path, false, null, 0, config('guard.max_file_read_bytes')) ?: '' : '';
        $matched = [];
        foreach ($this->rules->enabledRules() as $r) {
            $hit = match ($r['pattern_type']) { 'regex' => (bool)@preg_match($r['pattern'], $path), 'path' => fnmatch($r['pattern'], $path, FNM_PATHNAME | FNM_CASEFOLD) || fnmatch($r['pattern'], basename($path), FNM_CASEFOLD), default => $isPhp && stripos($content, $r['pattern']) !== false };
            if ($hit) $matched[] = $r;
        }
        $fnHits = array_values(array_filter($matched, fn($r)=>$r['type']==='suspicious_php'));
        $badHits = array_values(array_filter($matched, fn($r)=>$r['type']==='webshell'));
        $nameOnly = $fnHits && !$badHits && !$this->suspiciousContent($content) && !$this->suspiciousLocation($path) && !$this->malwareLikeName($path);
        $logIds = $this->relatedLogEventIds($path);
        if ($badHits || count($fnHits) >= 2 || ($fnHits && ($this->suspiciousLocation($path) || $this->malwareLikeName($path)))) {
            $risk = $allowed ? 'low' : ($nameOnly ? 'medium' : $this->maxRisk($matched));
            if ($logIds && !$allowed) $risk = $this->raiseRisk($risk);
            $out[] = ['risk'=>$risk, 'type'=>$badHits?'webshell':'suspicious_php', 'rule_key'=>'malware-indicators', 'title'=>$allowed?'Allowlisted suspicious file changed':'Suspicious PHP malware indicators', 'description'=>'Matched combined Jura AV Monitor rules.', 'matched'=>$matched, 'log_ids'=>$logIds];
        }
        if ($isPhp && is_writable($path) && $this->suspiciousLocation($path)) $out[] = ['risk'=>$allowed?'low':'medium','type'=>'writable_php','rule_key'=>'writable-risky-php','title'=>'Writable PHP in risky directory','description'=>'PHP file is writable inside upload/cache/temp-like path.','matched'=>[], 'log_ids'=>$logIds];
        if ($change === 'changed' && $this->importantChange($relative)) $out[] = ['risk'=>$allowed?'low':($this->criticalChange($relative)?'high':'medium'),'type'=>'core_change','rule_key'=>'important-change','title'=>'Important website file changed','description'=>'Snapshot detected change in an important CMS/core file.','matched'=>[], 'log_ids'=>$logIds];
        return $out;
    }

    private function knownFalsePositivePath(string $path): bool { foreach ((require base_path('rules/default-rules.php'))['allowlist'] as $p) if (fnmatch($p, $path, FNM_PATHNAME|FNM_CASEFOLD)) return true; return false; }
    private function suspiciousContent(string $content): bool { return (bool)preg_match('/(eval\s*\(|assert\s*\(|gzinflate\s*\(|base64_decode\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\()/i', $content); }
    private function malwareLikeName(string $path): bool { return (bool)preg_match('/\/(gallery888|zebra|mah|compat-kuro|AuthControlIer|access\.policy|session\.manage|field\.api|[a-f0-9]{12,})\.php$/i', $path); }
    private function suspiciousLocation(string $path): bool { foreach ((require base_path('rules/default-rules.php'))['suspicious_paths'] as $p) if (fnmatch($p, $path, FNM_PATHNAME|FNM_CASEFOLD)) return true; return false; }
    private function criticalChange(string $rel): bool { foreach ((require base_path('rules/default-rules.php'))['critical_changes'] as $p) if (fnmatch($p, $rel, FNM_PATHNAME|FNM_CASEFOLD)) return true; return false; }
    private function importantChange(string $rel): bool { $r=require base_path('rules/default-rules.php'); foreach (array_merge($r['critical_changes'],$r['important_changes']) as $p) if (fnmatch($p, $rel, FNM_PATHNAME|FNM_CASEFOLD)) return true; return false; }
    private function maxRisk(array $rules): string { $order=['low'=>1,'medium'=>2,'high'=>3,'critical'=>4]; $risk='low'; foreach($rules as $r) if(($order[$r['risk']]??0)>($order[$risk]??0)) $risk=$r['risk']; return $risk; }
    private function raiseRisk(string $risk): string { return ['low'=>'medium','medium'=>'high','high'=>'critical','critical'=>'critical'][$risk] ?? 'high'; }
    private function relatedLogEventIds(string $path): array { $base = basename($path); if (!$base) return []; return array_map(fn($r)=>(int)$r['id'], DB::select("SELECT id FROM log_events WHERE uri LIKE ? AND NOT (LOWER(uri) LIKE '%delivery.png%' OR LOWER(uri) IN ('/delivery','/ua/delivery','/ru/delivery')) ORDER BY id DESC LIMIT 20", ['%'.$base.'%'])); }

    private function upsertFinding(int $runId, int $siteId, string $path, array $m, array $f): void
    {
        $rules = json_encode(array_map(fn($r)=>['name'=>$r['name']??'runtime','risk'=>$r['risk']??$f['risk'],'pattern'=>$r['pattern']??''], $f['matched']), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        $fingerprint = hash('sha256', $path.'|'.$f['type'].'|'.($f['rule_key'] ?? '').'|'.($m['sha256'] ?? ''));
        $ignored = DB::first("SELECT id,sha256 FROM findings WHERE path=? AND type=? AND fingerprint=? AND status='ignored'", [$path,$f['type'],$fingerprint]);
        if ($ignored && ($ignored['sha256'] ?? null) === ($m['sha256'] ?? null)) return;
        $row = DB::first("SELECT id,status FROM findings WHERE path=? AND type=? AND fingerprint=? AND status NOT IN ('ignored','quarantined')", [$path,$f['type'],$fingerprint]);
        $logIds = json_encode($f['log_ids'] ?? [], JSON_UNESCAPED_SLASHES);
        if ($row) DB::statement('UPDATE findings SET scan_run_id=?,site_id=?,risk=?,rule_key=?,title=?,description=?,matched_rules=?,related_log_event_ids=?,sha256=?,size=?,mtime=?,owner=?,permissions=?,last_seen_at=?,updated_at=? WHERE id=?', [$runId,$siteId,$f['risk'],$f['rule_key'] ?? null,$f['title'],$f['description'],$rules,$logIds,$m['sha256'],$m['size'],$m['mtime'],$m['owner'],$m['permissions'],now(),now(),$row['id']]);
        else DB::insert('INSERT INTO findings (scan_run_id,site_id,path,risk,status,type,rule_key,fingerprint,title,description,matched_rules,related_log_event_ids,sha256,size,mtime,owner,permissions,first_seen_at,last_seen_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [$runId,$siteId,$path,$f['risk'],'new',$f['type'],$f['rule_key'] ?? null,$fingerprint,$f['title'],$f['description'],$rules,$logIds,$m['sha256'],$m['size'],$m['mtime'],$m['owner'],$m['permissions'],now(),now(),now(),now()]);
    }

    private function progress(array $options, string $message): void
    {
        if (($options['quiet'] ?? false) === true) return;
        echo '['.now().'] '.$message.PHP_EOL;
    }
}
