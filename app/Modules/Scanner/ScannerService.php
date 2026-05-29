<?php
namespace App\Modules\Scanner;

use App\Modules\Inventory\InventoryService;
use App\Modules\LogAnalyzer\LogAnalyzerService;
use App\Modules\Rules\RuleRepository;
use App\Support\DB;
use RecursiveDirectoryIterator; use RecursiveIteratorIterator; use FilesystemIterator; use Throwable;

class ScannerService
{
    public function __construct(private ?RuleRepository $rules = null) { $this->rules ??= new RuleRepository(); }
    public function scan(string $scopeType = 'full', ?string $scopeValue = null): int
    {
        $runId = DB::insert('INSERT INTO scan_runs (started_at,status,scope_type,scope_value,files_scanned,findings_count,created_at,updated_at) VALUES (?,?,?,?,0,0,?,?)', [now(),'running',$scopeType,$scopeValue,now(),now()]);
        $files = 0; $findings = 0;
        try {
            $inv = new InventoryService();
            $sites = match ($scopeType) { 'user' => $inv->refresh($scopeValue), 'site' => $inv->refresh(null, $scopeValue), default => $inv->refresh() };
            foreach ($sites as $site) {
                [$f, $c] = $this->scanSite($site, $runId); $files += $f; $findings += $c;
                DB::statement('UPDATE sites SET last_scan_at=?, updated_at=? WHERE id=?', [now(), now(), $site['id']]);
            }
            $logEvents = (new LogAnalyzerService())->analyze();
            DB::statement('UPDATE scan_runs SET status=?, finished_at=?, files_scanned=?, findings_count=?, updated_at=? WHERE id=?', ['completed', now(), $files, $findings, now(), $runId]);
            return $runId;
        } catch (Throwable $e) {
            DB::statement('UPDATE scan_runs SET status=?, finished_at=?, files_scanned=?, findings_count=?, error_text=?, updated_at=? WHERE id=?', ['failed', now(), $files, $findings, $e->getMessage(), now(), $runId]);
            throw $e;
        }
    }
    private function scanSite(array $site, int $runId): array
    {
        $count = 0; $findings = 0; $seen = [];
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($site['path'], FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            if (!$file->isFile() || $file->isLink()) continue;
            $path = $file->getPathname(); $seen[$path] = true; $count++;
            $meta = $this->meta($path); $relative = ltrim(str_replace($site['path'], '', $path), '/');
            $change = $this->snapshot($site['id'], $path, $relative, $meta);
            foreach ($this->detect($site, $path, $relative, $meta, $change) as $finding) { $this->upsertFinding($runId, $site['id'], $path, $meta, $finding); $findings++; }
        }
        foreach (DB::select('SELECT id,path FROM file_snapshots WHERE site_id=? AND is_missing=0', [$site['id']]) as $snap) if (!isset($seen[$snap['path']]) && !file_exists($snap['path'])) DB::statement('UPDATE file_snapshots SET is_missing=1,last_changed_at=?,updated_at=? WHERE id=?', [now(),now(),$snap['id']]);
        return [$count, $findings];
    }
    private function meta(string $path): array
    {
        $stat = @stat($path) ?: [];
        return ['size'=>filesize($path) ?: 0, 'mtime'=>isset($stat['mtime']) ? gmdate('Y-m-d H:i:s',$stat['mtime']) : null, 'sha256'=>hash_file('sha256',$path) ?: null, 'owner'=>function_exists('posix_getpwuid') ? (posix_getpwuid($stat['uid'] ?? 0)['name'] ?? (string)($stat['uid'] ?? '')) : (string)($stat['uid'] ?? ''), 'group'=>function_exists('posix_getgrgid') ? (posix_getgrgid($stat['gid'] ?? 0)['name'] ?? (string)($stat['gid'] ?? '')) : (string)($stat['gid'] ?? ''), 'permissions'=>substr(sprintf('%o', fileperms($path)), -4)];
    }
    private function snapshot(int $siteId, string $path, string $relative, array $m): string
    {
        $row = DB::first('SELECT * FROM file_snapshots WHERE path=?', [$path]);
        if (!$row) { DB::insert('INSERT INTO file_snapshots (site_id,path,relative_path,owner,"group",permissions,size,mtime,sha256,first_seen_at,last_seen_at,is_missing,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,0,?,?)', [$siteId,$path,$relative,$m['owner'],$m['group'],$m['permissions'],$m['size'],$m['mtime'],$m['sha256'],now(),now(),now(),now()]); return 'new'; }
        $changed = ($row['sha256'] !== $m['sha256'] || (string)$row['permissions'] !== (string)$m['permissions'] || (string)$row['owner'] !== (string)$m['owner'] || (int)$row['size'] !== (int)$m['size']);
        DB::statement('UPDATE file_snapshots SET site_id=?,relative_path=?,owner=?,"group"=?,permissions=?,size=?,mtime=?,sha256=?,last_seen_at=?,last_changed_at=CASE WHEN ? THEN ? ELSE last_changed_at END,is_missing=0,updated_at=? WHERE id=?', [$siteId,$relative,$m['owner'],$m['group'],$m['permissions'],$m['size'],$m['mtime'],$m['sha256'],now(),$changed?1:0,now(),now(),$row['id']]);
        return $changed ? 'changed' : 'same';
    }
    private function detect(array $site, string $path, string $relative, array $m, string $change): array
    {
        $out = []; $isPhp = str_ends_with(strtolower($path), '.php'); $allowed = $this->rules->isAllowed($path, $m['sha256']);
        $content = $isPhp ? @file_get_contents($path, false, null, 0, config('guard.max_file_read_bytes')) ?: '' : '';
        $matched = [];
        foreach ($this->rules->enabledRules() as $r) {
            $hit = match ($r['pattern_type']) { 'regex' => (bool)@preg_match($r['pattern'], $path), 'path' => fnmatch($r['pattern'], $path, FNM_PATHNAME | FNM_CASEFOLD) || fnmatch($r['pattern'], basename($path), FNM_CASEFOLD), default => $isPhp && stripos($content, $r['pattern']) !== false };
            if ($hit) $matched[] = $r;
        }
        $fnHits = array_values(array_filter($matched, fn($r)=>$r['type']==='suspicious_php'));
        $badHits = array_values(array_filter($matched, fn($r)=>$r['type']==='webshell'));
        if ($badHits || count($fnHits) >= 2 || ($fnHits && $this->suspiciousLocation($path))) $out[] = ['risk'=>$allowed?'low':$this->maxRisk($matched), 'type'=>$badHits?'webshell':'suspicious_php', 'title'=>$allowed?'Allowlisted suspicious file changed':'Suspicious PHP malware indicators', 'description'=>'Matched built-in Jura AV Monitor rules.', 'matched'=>$matched];
        if ($isPhp && is_writable($path) && $this->suspiciousLocation($path)) $out[] = ['risk'=>$allowed?'low':'medium','type'=>'writable_php','title'=>'Writable PHP in risky directory','description'=>'PHP file is writable inside upload/cache/temp-like path.','matched'=>[]];
        if ($change === 'changed' && $this->importantChange($relative)) $out[] = ['risk'=>$allowed?'low':($this->criticalChange($relative)?'high':'medium'),'type'=>'core_change','title'=>'Important website file changed','description'=>'Snapshot detected change in an important CMS/core file.','matched'=>[]];
        return $out;
    }
    private function suspiciousLocation(string $path): bool { foreach ((require base_path('rules/default-rules.php'))['suspicious_paths'] as $p) if (fnmatch($p, $path, FNM_PATHNAME|FNM_CASEFOLD)) return true; return false; }
    private function criticalChange(string $rel): bool { foreach ((require base_path('rules/default-rules.php'))['critical_changes'] as $p) if (fnmatch($p, $rel, FNM_PATHNAME|FNM_CASEFOLD)) return true; return false; }
    private function importantChange(string $rel): bool { $r=require base_path('rules/default-rules.php'); foreach (array_merge($r['critical_changes'],$r['important_changes']) as $p) if (fnmatch($p, $rel, FNM_PATHNAME|FNM_CASEFOLD)) return true; return false; }
    private function maxRisk(array $rules): string { $order=['low'=>1,'medium'=>2,'high'=>3,'critical'=>4]; $risk='low'; foreach($rules as $r) if(($order[$r['risk']]??0)>($order[$risk]??0)) $risk=$r['risk']; return $risk; }
    private function upsertFinding(int $runId, int $siteId, string $path, array $m, array $f): void
    {
        $rules = json_encode(array_map(fn($r)=>['name'=>$r['name']??'runtime','risk'=>$r['risk']??$f['risk'],'pattern'=>$r['pattern']??''], $f['matched']), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        $row = DB::first("SELECT id,status FROM findings WHERE path=? AND type=? AND status NOT IN ('ignored','quarantined')", [$path,$f['type']]);
        if ($row) DB::statement('UPDATE findings SET scan_run_id=?,site_id=?,risk=?,title=?,description=?,matched_rules=?,sha256=?,size=?,mtime=?,owner=?,permissions=?,last_seen_at=?,updated_at=? WHERE id=?', [$runId,$siteId,$f['risk'],$f['title'],$f['description'],$rules,$m['sha256'],$m['size'],$m['mtime'],$m['owner'],$m['permissions'],now(),now(),$row['id']]);
        else DB::insert('INSERT INTO findings (scan_run_id,site_id,path,risk,status,type,title,description,matched_rules,sha256,size,mtime,owner,permissions,first_seen_at,last_seen_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [$runId,$siteId,$path,$f['risk'],'new',$f['type'],$f['title'],$f['description'],$rules,$m['sha256'],$m['size'],$m['mtime'],$m['owner'],$m['permissions'],now(),now(),now(),now()]);
    }
}
