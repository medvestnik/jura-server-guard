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
    private int $skippedMedia = 0;
    public function __construct(private ?RuleRepository $rules = null) { $this->rules ??= new RuleRepository(); }

    public function scan(string $scopeType = 'full', ?string $scopeValue = null, array $options = []): int
    {
        $runId = DB::insert('INSERT INTO scan_runs (started_at,status,scope_type,scope_value,profile,files_scanned,skipped_media,skipped_directories,skipped_folders,findings_count,findings_new,created_at,updated_at) VALUES (?,?,?,?,?,0,0,0,0,0,0,?,?)', [now(),'running',$scopeType,$scopeValue,$this->profile($options),now(),now()]);
        $files = 0; $findings = 0;
        $stop = function (string $signal) use (&$runId, &$files, &$findings): void {
            DB::statement('UPDATE scan_runs SET status=?, finished_at=?, files_scanned=?, findings_count=?, findings_new=?, error_text=?, updated_at=? WHERE id=?', ['failed', now(), $files, $findings, $findings, $signal, now(), $runId]);
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
            $this->progress($options, sprintf('Scan #%d [%s]: %d site(s) selected for %s%s', $runId, $this->profile($options), count($sites), $scopeType, $scopeValue ? ': '.$scopeValue : '')); 
            foreach ($sites as $site) {
                [$f, $c] = $this->scanSite($site, $runId, $options); $files += $f; $findings += $c;
                DB::statement('UPDATE sites SET last_scan_at=?, updated_at=? WHERE id=?', [now(), now(), $site['id']]);
            }
            if (!($options['skip_logs'] ?? false)) (new LogAnalyzerService())->analyze();
            DB::statement('UPDATE scan_runs SET status=?, finished_at=?, files_scanned=?, findings_count=?, findings_new=?, skipped_media=?, skipped_directories=?, skipped_folders=?, updated_at=? WHERE id=?', ['completed', now(), $files, $findings, $findings, $this->skippedMedia, $this->skippedFolders, $this->skippedFolders, now(), $runId]);
            $this->progress($options, "Scan #$runId completed: files=$files findings=$findings skipped_media={$this->skippedMedia} skipped_folders={$this->skippedFolders}");
            return $runId;
        } catch (Throwable $e) {
            DB::statement('UPDATE scan_runs SET status=?, finished_at=?, files_scanned=?, findings_count=?, findings_new=?, error_text=?, updated_at=? WHERE id=?', ['failed', now(), $files, $findings, $findings, $e->getMessage(), now(), $runId]);
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
            $path = $file->getPathname();
            if (!$this->shouldScanFile($path, $site['path'], $options)) { $this->skippedMedia++; continue; }
            $seen[$path] = true; $count++;
            $relative = ltrim(str_replace($site['path'], '', $path), '/');
            $pathHash = hash('sha256', $path);
            $previous = DB::first('SELECT * FROM file_snapshots WHERE path_hash=? AND path=?', [$pathHash, $path]);
            $meta = $this->meta($path, $previous, $relative);
            $change = $dryRun ? 'dry-run' : $this->snapshot($site['id'], $path, $pathHash, $relative, $meta, $previous);
            foreach ($this->detect($site, $path, $relative, $meta, $change) as $finding) {
                if (!$dryRun) $this->upsertFinding($runId, $site['id'], $path, $meta, $finding);
                $findings++;
            }
            if ($count % 1000 === 0) $this->progress($options, "Progress {$site['name']}: files=$count findings=$findings elapsed=".(time()-$start).'s');
        }
        if (!$dryRun) foreach (DB::select('SELECT id,path FROM file_snapshots WHERE site_id=? AND is_missing=0', [$site['id']]) as $snap) if (!isset($seen[$snap['path']]) && !file_exists($snap['path'])) DB::statement('UPDATE file_snapshots SET is_missing=1,last_changed_at=?,updated_at=? WHERE id=?', [now(),now(),$snap['id']]);
        $this->progress($options, "Finished {$site['name']}: files=$count findings=$findings skipped_media={$this->skippedMedia} skipped_folders={$this->skippedFolders} elapsed=".(time()-$start).'s');
        return [$count, $findings];
    }


    private function profile(array $options): string
    {
        $profile = strtolower((string)($options['profile'] ?? config('guard.scan_profile', 'fast')));
        return in_array($profile, ['fast','standard','deep'], true) ? $profile : 'fast';
    }

    private function shouldScanFile(string $path, string $root, array $options): bool
    {
        $profile = $this->profile($options);
        if ($profile === 'deep') return true;
        $rel = ltrim(str_replace($root, '', $path), '/');
        if ($this->isValidationPath($path) || $this->isRootCriticalFile($rel) || $this->isWebConfig($path) || $this->isPhpLike($path)) return true;
        $lower = strtolower($path);
        if ($profile === 'fast') return false;
        if (preg_match('/\.(js|html?|shtml|svg)$/i', $path)) return true;
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

    private function snapshot(int $siteId, string $path, string $pathHash, string $relative, array $m, ?array $row): string
    {
        $groupCol = DB::quoteIdentifier('group');
        if (!$row) { DB::insert("INSERT INTO file_snapshots (site_id,path,path_hash,relative_path,owner,$groupCol,permissions,size,mtime,sha256,first_seen_at,last_seen_at,is_missing,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)", [$siteId,$path,$pathHash,$relative,$m['owner'],$m['group'],$m['permissions'],$m['size'],$m['mtime'],$m['sha256'],now(),now(),now(),now()]); return 'new'; }
        $changed = ($row['sha256'] !== $m['sha256'] || (string)$row['mtime'] !== (string)$m['mtime'] || (string)$row['permissions'] !== (string)$m['permissions'] || (string)$row['owner'] !== (string)$m['owner'] || (int)$row['size'] !== (int)$m['size']);
        DB::statement("UPDATE file_snapshots SET site_id=?,path_hash=?,relative_path=?,owner=?,$groupCol=?,permissions=?,size=?,mtime=?,sha256=?,last_seen_at=?,last_changed_at=CASE WHEN ? THEN ? ELSE last_changed_at END,is_missing=0,updated_at=? WHERE id=?", [$siteId,$pathHash,$relative,$m['owner'],$m['group'],$m['permissions'],$m['size'],$m['mtime'],$m['sha256'],now(),$changed?1:0,now(),now(),$row['id']]);
        return $changed ? 'changed' : 'same';
    }

    private function detect(array $site, string $path, string $relative, array $m, string $change): array
    {
        $out = []; $isPhp = $this->isPhpLike($path); $explicitlyAllowed = $this->rules->isAllowed($path, $m['sha256']);
        $content = ($isPhp || $this->isWebConfig($path) || $this->isValidationPath($path)) ? @file_get_contents($path, false, null, 0, config('guard.max_file_read_bytes')) ?: '' : '';
        $loaderEvidence = $this->selfReadingPackedLoaderEvidence($content);
        $allowed = $explicitlyAllowed || ($this->knownFalsePositivePath($path) && !$loaderEvidence);
        $logIds = $this->relatedLogEventIds($path);
        if ($this->isValidationPath($path) && ($isPhp || $this->isWebConfig($path))) {
            $risk = $allowed ? 'low' : ($this->fakeWellKnownPath($path) || $isPhp ? 'critical' : 'high');
            $out[] = ['risk'=>$risk,'type'=>'validation_path_malware','rule_key'=>'validation-path-executable','title'=>'Executable or config file under validation directory','description'=>($this->fakeWellKnownPath($path)?'Fake well-known directory without leading dot is suspicious. ':'').'Validation/ACME paths should not contain PHP loaders or dangerous handlers.','matched'=>[], 'log_ids'=>$logIds];
        }
        if ($loaderEvidence) $out[] = ['risk'=>$allowed?'low':'critical','type'=>'packed_loader','rule_key'=>'self-reading-packed-loader','title'=>'Self-reading packed PHP loader','description'=>'Detected eval with gzuncompress/gzinflate, self-reading file_get_contents(__FILE__), and a negative substr offset or appended binary/compressed payload.','matched'=>[$loaderEvidence], 'log_ids'=>$logIds];
        $matched = [];
        foreach ($this->rules->enabledRules() as $r) {
            $hit = match ($r['pattern_type']) { 'regex' => (bool)@preg_match($r['pattern'], $path), 'path' => fnmatch($r['pattern'], $path, FNM_PATHNAME | FNM_CASEFOLD) || fnmatch($r['pattern'], basename($path), FNM_CASEFOLD), default => $isPhp && stripos($content, $r['pattern']) !== false };
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
        if ($change === 'changed' && $this->importantChange($relative)) $out[] = ['risk'=>$allowed?'low':($this->criticalChange($relative)?'high':'medium'),'type'=>'core_change','rule_key'=>'important-change','title'=>'Important website file changed','description'=>'Snapshot detected change in an important CMS/core file.','matched'=>[], 'log_ids'=>$logIds];
        return $out;
    }

    private function knownFalsePositivePath(string $path): bool { foreach ((require base_path('rules/default-rules.php'))['allowlist'] as $p) if (fnmatch($p, $path, FNM_PATHNAME|FNM_CASEFOLD)) return true; return false; }
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
    private function suspiciousLocation(string $path): bool { foreach ((require base_path('rules/default-rules.php'))['suspicious_paths'] as $p) if (fnmatch($p, $path, FNM_PATHNAME|FNM_CASEFOLD)) return true; return false; }
    private function criticalChange(string $rel): bool { foreach ((require base_path('rules/default-rules.php'))['critical_changes'] as $p) if (fnmatch($p, $rel, FNM_PATHNAME|FNM_CASEFOLD)) return true; return false; }
    private function importantChange(string $rel): bool { $r=require base_path('rules/default-rules.php'); foreach (array_merge($r['critical_changes'],$r['important_changes']) as $p) if (fnmatch($p, $rel, FNM_PATHNAME|FNM_CASEFOLD)) return true; return false; }
    private function maxRisk(array $rules): string { $order=['low'=>1,'medium'=>2,'high'=>3,'critical'=>4]; $risk='low'; foreach($rules as $r) if(($order[$r['risk']]??0)>($order[$risk]??0)) $risk=$r['risk']; return $risk; }
    private function raiseRisk(string $risk): string { return ['low'=>'medium','medium'=>'high','high'=>'critical','critical'=>'critical'][$risk] ?? 'high'; }
    private function relatedLogEventIds(string $path): array { $base = basename($path); if (!$base) return []; return array_map(fn($r)=>(int)$r['id'], DB::select("SELECT id FROM log_events WHERE uri LIKE ? AND NOT (LOWER(uri) LIKE '%delivery.png%' OR LOWER(uri) IN ('/delivery','/ua/delivery','/ru/delivery')) ORDER BY id DESC LIMIT 20", ['%'.$base.'%'])); }

    private function upsertFinding(int $runId, int $siteId, string $path, array $m, array $f): void
    {
        $rules = json_encode(array_map(fn($r)=>array_filter(['name'=>$r['name']??'runtime','risk'=>$r['risk']??$f['risk'],'pattern'=>$r['pattern']??'','snippet'=>$r['snippet']??null,'why'=>$r['why']??null,'indicators'=>$r['indicators']??null], fn($v)=>$v !== null), $f['matched']), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        $pathHash = hash('sha256', $path);
        $fingerprint = hash('sha256', $path.'|'.$f['type'].'|'.($f['rule_key'] ?? '').'|'.($m['sha256'] ?? ''));
        $findingHash = hash('sha256', $path.'|'.$f['type'].'|'.($f['rule_key'] ?? '').'|'.$fingerprint);
        $ignored = DB::first("SELECT id,sha256 FROM findings WHERE finding_hash=? AND path_hash=? AND path=? AND status='ignored'", [$findingHash,$pathHash,$path]);
        if ($ignored && ($ignored['sha256'] ?? null) === ($m['sha256'] ?? null)) return;
        $row = DB::first("SELECT id,status FROM findings WHERE finding_hash=? AND path_hash=? AND path=? AND status NOT IN ('ignored','quarantined')", [$findingHash,$pathHash,$path]);
        $logIds = json_encode($f['log_ids'] ?? [], JSON_UNESCAPED_SLASHES);
        if ($row) DB::statement('UPDATE findings SET scan_run_id=?,site_id=?,path_hash=?,finding_hash=?,risk=?,rule_key=?,title=?,description=?,matched_rules=?,related_log_event_ids=?,sha256=?,size=?,mtime=?,owner=?,permissions=?,last_seen_at=?,updated_at=? WHERE id=?', [$runId,$siteId,$pathHash,$findingHash,$f['risk'],$f['rule_key'] ?? null,$f['title'],$f['description'],$rules,$logIds,$m['sha256'],$m['size'],$m['mtime'],$m['owner'],$m['permissions'],now(),now(),$row['id']]);
        else DB::insert('INSERT INTO findings (scan_run_id,site_id,path,path_hash,finding_hash,risk,status,type,rule_key,fingerprint,title,description,matched_rules,related_log_event_ids,sha256,size,mtime,owner,permissions,first_seen_at,last_seen_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [$runId,$siteId,$path,$pathHash,$findingHash,$f['risk'],'new',$f['type'],$f['rule_key'] ?? null,$fingerprint,$f['title'],$f['description'],$rules,$logIds,$m['sha256'],$m['size'],$m['mtime'],$m['owner'],$m['permissions'],now(),now(),now(),now()]);
    }

    private function progress(array $options, string $message): void
    {
        if (($options['quiet'] ?? false) === true) return;
        echo '['.now().'] '.$message.PHP_EOL;
    }
}
