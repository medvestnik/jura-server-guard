<?php
function utc_timestamp(string $timestamp): int { return strtotime($timestamp . ' UTC') ?: strtotime($timestamp) ?: time(); }
require dirname(__DIR__).'/vendor/autoload.php';
use App\Support\Auth; use App\Support\DB; use App\Support\ScanLock; use App\Modules\Quarantine\QuarantineService; use App\Modules\Quarantine\BulkFindingActionService; use App\Modules\Scanner\ScannerService; use App\Modules\Scanner\SignatureEngine; use App\Modules\Backups\IspmanagerBackupService; use App\Modules\Incidents\IncidentImportService; use App\Modules\Ai\SignatureSuggestionService; use App\Modules\Ai\ChatService; use App\Modules\Abuse\AbuseReportService; use App\Modules\Firewall\IpBlockService;
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
try { DB::pdo(); } catch (Throwable $e) { echo 'Database not initialized. Run php artisan migrate.'; exit; }
if (preg_match('#^/lang/([a-z]{2})$#', $path, $m) && array_key_exists($m[1], available_locales())) { setcookie('jura_lang', $m[1], time() + 31536000, '/', '', false, true); redirect($_SERVER['HTTP_REFERER'] ?? '/'); }
if ($path === '/login' && $method === 'POST') { Auth::attempt($_POST['email'] ?? '', $_POST['password'] ?? '') ? redirect('/') : print view('auth.login', ['error'=>'Invalid credentials']); exit; }
if ($path === '/login') { echo view('auth.login'); exit; }
if ($path === '/logout') { Auth::logout(); redirect('/login'); }
Auth::require();


function scan_pid_alive(int $pid): bool { return $pid > 0 && (function_exists('posix_kill') ? @posix_kill($pid, 0) : is_dir('/proc/'.$pid)); }
function scan_active_context(): array {
    if (DB::first("SELECT id FROM scan_runs WHERE status='running' AND total_files_estimated > 0 AND files_scanned >= total_files_estimated LIMIT 1")) { DB::statement("UPDATE scan_runs SET status='completed', finished_at=?, error_text=?, last_heartbeat_at=?, progress_message=?, updated_at=? WHERE status='running' AND total_files_estimated > 0 AND files_scanned >= total_files_estimated", [now(), 'Auto-completed by web active-scan context because progress reached 100%', now(), 'Auto-completed stale 100% scan', now()]); (new ScanLock())->unlock(true); }
    $run = DB::first("SELECT * FROM scan_runs WHERE status='running' AND NOT (total_files_estimated > 0 AND files_scanned >= total_files_estimated) ORDER BY id DESC LIMIT 1");
    $lock = (new ScanLock())->read();
    $pid = (int)($run['pid'] ?? $lock['pid'] ?? 0);
    $pidAlive = $pid > 0 && scan_pid_alive($pid);
    $heartbeatAge = !empty($run['last_heartbeat_at']) ? max(0, time() - utc_timestamp($run['last_heartbeat_at'])) : null;
    $lockAge = !empty($lock['started_at']) ? max(0, time() - utc_timestamp($lock['started_at'])) : null;
    $stale = (bool)$run && ((!$pidAlive && $pid > 0) || ($heartbeatAge !== null && $heartbeatAge > 90));
    if (!$run && $lock && !$pidAlive && ($lockAge === null || $lockAge > 90)) $stale = true;
    $total = isset($run['total_files_estimated']) ? (int)$run['total_files_estimated'] : 0;
    $files = isset($run['files_scanned']) ? (int)$run['files_scanned'] : 0;
    $progress = $total > 0 ? min(100, round($files * 100 / $total, 1)) : null;
    return ['run'=>$run, 'lock'=>$lock, 'running'=>(bool)$run || (bool)$lock, 'stale'=>$stale, 'pid_alive'=>$pidAlive, 'pid'=>$pid, 'heartbeat_age'=>$heartbeatAge, 'progress'=>$progress];
}
function scan_is_stale(?array $run): bool { return scan_active_context()['stale']; }
function format_duration(int $seconds): string { return sprintf('%02d:%02d:%02d', intdiv($seconds,3600), intdiv($seconds%3600,60), $seconds%60); }
function start_background_scan(string $scope, ?string $value, string $profile, ?int $maxSeconds = null): void {
    $php = trim((string)env_value('JURA_PHP_BIN', '')) ?: PHP_BINARY;
    $cmd = [$php, base_path('artisan'), $scope === 'site' ? 'guard:scan-site' : ($scope === 'user' ? 'guard:scan-user' : 'guard:scan')];
    if ($scope !== 'full') $cmd[] = (string)$value;
    $cmd[] = '--profile='.$profile;
    if ($maxSeconds !== null) $cmd[] = '--max-seconds='.$maxSeconds;
    $cmd[] = '--lock-label=web scan '.$scope.' '.$profile;
    $parts = array_map('escapeshellarg', $cmd);
    $out = storage_path('logs/web-scan.log');
    if (!is_dir(dirname($out))) mkdir(dirname($out), 0750, true);
    exec(implode(' ', $parts).' >> '.escapeshellarg($out).' 2>&1 &');
}
function start_background_bulk_finding_action(string $id): void {
    $php = trim((string)env_value('JURA_PHP_BIN', '')) ?: PHP_BINARY;
    $out = storage_path('logs/bulk-finding-actions.log');
    if (!is_dir(dirname($out))) mkdir(dirname($out), 0750, true);
    $cmd = escapeshellarg($php).' '.escapeshellarg(base_path('artisan')).' guard:findings-bulk-action '.escapeshellarg($id);
    exec($cmd.' >> '.escapeshellarg($out).' 2>&1 &');
}
function back_url(): string { return $_SERVER['HTTP_REFERER'] ?? '/'; }
function safe_finding_preview(?array $finding): array {
    if (!$finding) return ['content'=>'', 'source'=>null, 'error'=>'Finding not found.'];
    $path = (string)($finding['path'] ?? '');
    $source = $path;
    if (!is_readable($source)) {
        $item = DB::first("SELECT quarantine_path FROM quarantine_items WHERE finding_id=? AND status='quarantined' ORDER BY id DESC LIMIT 1", [(int)$finding['id']]);
        if ($item && is_readable($item['quarantine_path'])) $source = $item['quarantine_path'];
    }
    if (!is_file($source)) return ['content'=>'', 'source'=>null, 'error'=>'File no longer exists at its original path or in quarantine.'];
    if (!is_readable($source)) return ['content'=>'', 'source'=>$source, 'error'=>'The panel process cannot read this file.'];
    $limit = max(1, min((int)config('guard.max_file_read_bytes'), 1048576));
    $content = file_get_contents($source, false, null, 0, $limit);
    if ($content === false) return ['content'=>'', 'source'=>$source, 'error'=>'Failed to read file content.'];
    $truncated = filesize($source) > strlen($content);
    if (str_contains($content, "\0")) {
        $content = trim(chunk_split(bin2hex(substr($content, 0, min(strlen($content), 8192))), 32, "\n"));
        return ['content'=>$content, 'source'=>$source, 'error'=>null, 'truncated'=>$truncated, 'binary'=>true];
    }
    return ['content'=>$content, 'source'=>$source, 'error'=>null, 'truncated'=>$truncated, 'binary'=>false];
}

function send_csv(string $filename, array $rows): void {
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="'.$filename.'"');
    $out = fopen('php://output', 'w');
    if ($rows) { fputcsv($out, array_keys($rows[0])); foreach ($rows as $row) fputcsv($out, $row); }
    fclose($out); exit;
}
function send_json(string $filename, mixed $data): void {
    header('Content-Type: application/json; charset=UTF-8');
    header('Content-Disposition: attachment; filename="'.$filename.'"');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
function finding_filters(?array $source = null): array {
    $source = $source ?? $_GET;
    $where=[]; $params=[];
    foreach (['risk'=>'f.risk','status'=>'f.status','type'=>'f.type'] as $key=>$col) if (($source[$key]??'')!=='') { $where[]="$col=?"; $params[]=$source[$key]; }
    if (($source['user']??'')!=='') { $where[]='u.name LIKE ?'; $params[]='%'.trim((string)$source['user']).'%'; }
    if (($source['site']??'')!=='') { $where[]='s.name LIKE ?'; $params[]='%'.trim((string)$source['site']).'%'; }
    if (($source['path']??'')!=='') { $where[]='f.path LIKE ?'; $params[]='%'.$source['path'].'%'; }
    if (($source['date_from']??'')!=='') { $where[]='f.last_seen_at >= ?'; $params[]=$source['date_from'].' 00:00:00'; }
    if (($source['date_to']??'')!=='') { $where[]='f.last_seen_at <= ?'; $params[]=$source['date_to'].' 23:59:59'; }
    return [$where ? 'WHERE '.implode(' AND ', $where) : '', $params];
}

function resolve_bulk_finding_ids(): array {
    if (($_POST['select_all_filtered'] ?? '') === '1') {
        [$w,$p] = finding_filters((array)($_POST['back_query'] ?? []));
        $rows = DB::select("SELECT f.id FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id $w", $p);
        return array_map(fn($r)=>(int)$r['id'], $rows);
    }
    return array_values(array_unique(array_filter(array_map('intval', (array)($_POST['ids'] ?? [])))));
}

function findings_pagination(int $total): array {
    $options=[];
    foreach ((array)config('guard.pagination_options', ['20','50','100','200','500','all']) as $value) {
        $value=strtolower(trim((string)$value));
        if ($value==='all') { $options[]='all'; continue; }
        $size=(int)$value;
        if ($size > 0 && $size <= 10000) $options[]=(string)$size;
    }
    $options=array_values(array_unique($options));
    if (!$options) $options=['20','50','100','200','500','all'];
    $default=strtolower(trim((string)config('guard.pagination_default', '50')));
    if (!in_array($default,$options,true)) $default=in_array('50',$options,true)?'50':$options[0];
    $perPage=strtolower(trim((string)($_GET['per_page']??$default)));
    if (!in_array($perPage,$options,true)) $perPage=$default;
    if ($perPage==='all') return ['options'=>$options,'per_page'=>'all','page'=>1,'total_pages'=>1,'from'=>$total?1:0,'to'=>$total,'sql'=>''];
    $size=(int)$perPage;
    $totalPages=max(1,(int)ceil($total/$size));
    $page=min(max(1,(int)($_GET['page']??1)),$totalPages);
    $offset=($page-1)*$size;
    return ['options'=>$options,'per_page'=>$perPage,'page'=>$page,'total_pages'=>$totalPages,'from'=>$total?($offset+1):0,'to'=>min($total,$offset+$size),'sql'=>' LIMIT '.$size.' OFFSET '.$offset];
}

function file_change_filters(): array {
    $where=[]; $params=[]; $kind=$_GET['kind']??'';
    if (($_GET['path']??'')!=='') { $where[]='fs.path LIKE ?'; $params[]='%'.$_GET['path'].'%'; }
    if ($kind==='new') $where[]='fs.first_seen_at = fs.last_seen_at AND fs.is_missing=0';
    if ($kind==='modified') $where[]='fs.last_changed_at IS NOT NULL AND fs.is_missing=0';
    if ($kind==='deleted') $where[]='fs.is_missing=1';
    if ($kind==='webroot') $where[]="fs.relative_path NOT LIKE '%/%'";
    if ($kind==='htaccess') $where[]="fs.path LIKE '%.htaccess%'";
    if ($kind==='google') $where[]="fs.relative_path LIKE 'google%.html'";
    if ($kind==='php') $where[]="fs.path LIKE '%.php'";
    if ($kind==='html') $where[]="(fs.path LIKE '%.html' OR fs.path LIKE '%.htm')";
    if ($kind==='seo') $where[]="(LOWER(fs.path) LIKE '%denza%' OR LOWER(fs.path) LIKE '%casino%' OR LOWER(fs.path) LIKE '%slot%' OR LOWER(fs.path) LIKE '%mahjong%' OR LOWER(fs.path) LIKE '%judi%' OR LOWER(fs.path) LIKE '%gacor%')";
    if ($kind==='skipped') $where[]='fs.last_seen_scan_id IS NOT NULL AND (fs.last_changed_scan_id IS NULL OR fs.last_changed_scan_id <> fs.last_seen_scan_id) AND fs.is_missing=0';
    if ($kind==='suspicious') $where[]="(fs.last_changed_scan_id = fs.last_seen_scan_id AND (LOWER(fs.path) LIKE '%.php' OR LOWER(fs.path) LIKE '%.phtml' OR fs.path LIKE '%.htaccess%' OR LOWER(fs.path) LIKE '%/uploads/%' OR LOWER(fs.path) LIKE '%/cache/%' OR LOWER(fs.path) LIKE '%404sbg%' OR LOWER(fs.path) LIKE '%configcwe%' OR LOWER(fs.path) LIKE '%fss-npy%'))";
    return [$where ? 'WHERE '.implode(' AND ', $where) : '', $params];
}

function signature_filters(): array { $w=[]; $p=[]; foreach(['enabled'=>'enabled','risk'=>'risk','type'=>'type','source'=>'source'] as $k=>$c) if(($_GET[$k]??'')!==''){ $w[]="$c=?"; $p[]=$_GET[$k]; } return [$w?'WHERE '.implode(' AND ',$w):'', $p]; }
if ($path === '/signatures/toggle' && $method==='POST') { DB::statement('UPDATE malware_signatures SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END, updated_at=? WHERE id=?',[now(),(int)$_POST['id']]); redirect('/signatures'); }
if ($path === '/signatures/delete' && $method==='POST') { DB::statement('DELETE FROM malware_signatures WHERE id=?',[(int)$_POST['id']]); redirect('/signatures'); }
if ($path === '/signatures/duplicate' && $method==='POST') { $r=DB::first('SELECT * FROM malware_signatures WHERE id=?',[(int)$_POST['id']]); if($r) DB::insert('INSERT INTO malware_signatures (name,slug,description,risk,type,pattern_type,pattern_json,target_extensions,target_paths,exclude_paths,required_hits,enabled,source,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',[$r['name'].' copy',$r['slug'].'-copy-'.time(),$r['description'],$r['risk'],$r['type'],$r['pattern_type'],$r['pattern_json'],$r['target_extensions'],$r['target_paths'],$r['exclude_paths'],$r['required_hits'],0,'manual',now(),now()]); redirect('/signatures'); }
if ($path === '/signatures/save' && $method==='POST') { $id=(int)($_POST['id']??0); $slug=$_POST['slug'] ?: strtolower(preg_replace('/[^a-z0-9]+/i','-',$_POST['name'])); if($id) DB::statement('UPDATE malware_signatures SET name=?,slug=?,description=?,risk=?,type=?,pattern_type=?,pattern_json=?,source=?,updated_at=? WHERE id=?',[$_POST['name'],$slug,$_POST['description'],$_POST['risk'],$_POST['type'],$_POST['pattern_type'],$_POST['pattern_json'],'manual',now(),$id]); else $id=DB::insert('INSERT INTO malware_signatures (name,slug,description,risk,type,pattern_type,pattern_json,target_extensions,enabled,source,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,1,?,?,?)',[$_POST['name'],$slug,$_POST['description'],$_POST['risk'],$_POST['type'],$_POST['pattern_type'],$_POST['pattern_json'],'[]','manual',now(),now()]); redirect('/signatures/'.$id); }
if ($path === '/finding/signature-suggest' && $method==='POST') { $id=(int)$_POST['id']; if(DB::first('SELECT id FROM findings WHERE id=?',[$id])) { try { (new SignatureSuggestionService())->suggest($id); } catch (Throwable $e) {} } redirect('/findings/'.$id); }
if ($path === '/signatures/suggestions') { echo view('signatures.suggestions', ['suggestions'=>DB::select('SELECT ss.*, f.path finding_path FROM signature_suggestions ss LEFT JOIN findings f ON f.id=ss.finding_id ORDER BY ss.id DESC LIMIT 200')]); exit; }
if ($path === '/signatures/create-from-suggestion') {
    $sid = (int)($_GET['id'] ?? 0);
    $s = DB::first('SELECT * FROM signature_suggestions WHERE id=?', [$sid]);
    if (!$s) redirect('/signatures/suggestions');
    echo view('signatures.form', ['signature' => ['name' => $s['suggested_name'], 'slug' => 'ai-' . $sid . '-' . time(), 'risk' => $s['suggested_risk'], 'type' => $s['suggested_type'], 'pattern_type' => $s['suggested_pattern_type'], 'pattern_json' => $s['suggested_pattern_json'], 'description' => $s['explanation']], 'preview' => '']);
    exit;
}
if ($path === '/finding/create-signature' && $method==='POST') { $f=DB::first('SELECT * FROM findings WHERE id=?',[(int)$_POST['id']]); $hasHash=!empty($f['sha256']); $preview=($f&&is_readable($f['path']))?file_get_contents($f['path'],false,null,0,min(config('guard.max_file_read_bytes'),65536)):''; echo view('signatures.form',['signature'=>['name'=>'Signature from finding '.$f['id'],'slug'=>'finding-'.$f['id'].'-'.time(),'risk'=>$f['risk'],'type'=>$f['type'],'pattern_type'=>$hasHash?'hash':'combo','pattern_json'=>$hasHash?json_encode(['sha256'=>[$f['sha256']]]):'{}','description'=>$f['description']],'preview'=>$preview]); exit; }

if ($path === '/ai-chat') {
    if (!config('guard.ai_chat_enabled')) redirect('/');
    $adminId = (int) ($_SESSION['admin_id'] ?? 0);
    echo view('ai_chat.index', ['messages' => (new ChatService())->history($adminId)]);
    exit;
}
if ($path === '/ai-chat/send' && $method === 'POST' && config('guard.ai_chat_enabled')) {
    $adminId = (int) ($_SESSION['admin_id'] ?? 0);
    $text = trim((string) ($_POST['message'] ?? ''));
    if ($text !== '') { try { (new ChatService())->send($adminId, $text); } catch (Throwable $e) {} }
    redirect('/ai-chat');
}
if ($path === '/ai-chat/confirm' && $method === 'POST' && config('guard.ai_chat_enabled')) {
    (new ChatService())->resolvePending((int) ($_POST['id'] ?? 0), true);
    redirect('/ai-chat');
}
if ($path === '/ai-chat/cancel' && $method === 'POST' && config('guard.ai_chat_enabled')) {
    (new ChatService())->resolvePending((int) ($_POST['id'] ?? 0), false);
    redirect('/ai-chat');
}
if ($path === '/ai-chat/clear' && $method === 'POST' && config('guard.ai_chat_enabled')) {
    (new ChatService())->clear((int) ($_SESSION['admin_id'] ?? 0));
    redirect('/ai-chat');
}

function log_filters(): array {
    $where=[]; $params=[];
    if ((int)($_GET['event_id']??0) > 0) { $where[]='l.id=?'; $params[]=(int)$_GET['event_id']; }
    foreach (['risk'=>'l.risk','type'=>'l.event_type','ip'=>'l.ip'] as $key=>$col) if (($_GET[$key]??'')!=='') { $where[]="$col=?"; $params[]=$_GET[$key]; }
    if (($_GET['uri']??'')!=='') { $where[]='l.uri LIKE ?'; $params[]='%'.$_GET['uri'].'%'; }
    if (($_GET['site']??'')!=='') { $where[]='s.name=?'; $params[]=$_GET['site']; }
    if (($_GET['date_from']??'')!=='') { $where[]='l.created_at >= ?'; $params[]=$_GET['date_from'].' 00:00:00'; }
    if (($_GET['date_to']??'')!=='') { $where[]='l.created_at <= ?'; $params[]=$_GET['date_to'].' 23:59:59'; }
    return [$where ? 'WHERE '.implode(' AND ', $where) : '', $params];
}

function log_event_with_site(int $eventId, string $ip): ?array
{
    $event = DB::first('SELECT l.*,s.name site_name FROM log_events l LEFT JOIN sites s ON s.id=l.site_id WHERE l.id=? AND l.ip=?', [$eventId,$ip]);
    if (!$event || !empty($event['site_name'])) return $event;
    $logPath = strtolower((string)($event['log_path'] ?? ''));
    foreach (DB::select('SELECT id,name FROM sites ORDER BY LENGTH(name) DESC') as $site) {
        if ($site['name'] !== '' && str_contains($logPath, strtolower((string)$site['name']))) { $event['site_id']=$site['id']; $event['site_name']=$site['name']; break; }
    }
    return $event;
}

function save_threat_ip_evidence(int $threatIpId, int $eventId, string $ip): bool
{
    if ($eventId < 1) return false;
    $event = log_event_with_site($eventId, $ip);
    if (!$event || DB::first('SELECT id FROM threat_ip_evidence WHERE threat_ip_id=? AND log_event_id=?', [$threatIpId,$eventId])) return false;
    $requestPath = parse_url((string)($event['uri'] ?? ''), PHP_URL_PATH) ?: null;
    DB::insert('INSERT INTO threat_ip_evidence (threat_ip_id,log_event_id,site_id,site_name,request_uri,file_path,detected_at,created_at) VALUES (?,?,?,?,?,?,?,?)', [$threatIpId,$eventId,$event['site_id'],$event['site_name'],$event['uri'],$requestPath,$event['created_at'],now()]);
    DB::statement('UPDATE threat_ips SET hit_count=hit_count+1 WHERE id=?', [$threatIpId]);
    return true;
}

if ($path === '/finding/ignore' && $method==='POST') { DB::statement('UPDATE findings SET status=?, updated_at=? WHERE id=?', ['ignored', now(), (int)$_POST['id']]); redirect('/findings/'.(int)$_POST['id']); }
if ($path === '/finding/allowlist' && $method==='POST') { $f=DB::first('SELECT * FROM findings WHERE id=?',[(int)$_POST['id']]); if($f) DB::insert('INSERT INTO allowlist_rules (name,path_pattern,sha256,reason,enabled,created_at,updated_at) VALUES (?,?,?,?,1,?,?)',['Web allowlist '.$f['id'],$f['path'],$f['sha256'],'Added from finding page',now(),now()]); redirect('/rules'); }
if ($path === '/finding/quarantine' && $method==='POST' && config('guard.web_actions_enabled')) { (new QuarantineService())->quarantine((int)$_POST['id'], 'Web panel quarantine'); redirect(($_POST['return_to'] ?? '') === 'findings' ? '/findings?quarantined='.(int)$_POST['id'] : '/quarantine'); }
if ($path === '/finding/delete' && $method==='POST' && config('guard.web_actions_enabled')) {
    $id=(int)($_POST['id']??0);
    try { (new QuarantineService())->delete($id, 'Permanent deletion from Findings web panel'); redirect('/findings?deleted='.$id); }
    catch (Throwable $e) { redirect('/findings?'.http_build_query(['delete_error'=>$e->getMessage()])); }
}
if ($path === '/quarantine/restore' && $method==='POST' && config('guard.web_actions_enabled')) { (new QuarantineService())->restore((int)$_POST['id']); redirect('/quarantine'); }
if ($path === '/findings/bulk-status' && $method==='GET') {
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store');
    try { echo json_encode((new BulkFindingActionService())->status((string)($_GET['id']??'')), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); }
    catch (Throwable $e) { http_response_code(404); echo json_encode(['status'=>'failed','error'=>$e->getMessage()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); }
    exit;
}
if (in_array($path, ['/findings/bulk-quarantine','/findings/bulk-delete'], true) && $method==='POST' && config('guard.web_actions_enabled')) {
    $action=$path==='/findings/bulk-delete'?'delete':'quarantine';
    try {
        $job=(new BulkFindingActionService())->create($action, resolve_bulk_finding_ids());
        start_background_bulk_finding_action($job);
        redirect('/findings?'.http_build_query(array_merge($_POST['back_query']??[], ['bulk_job'=>$job])));
    } catch (Throwable $e) {
        redirect('/findings?'.http_build_query(array_merge($_POST['back_query']??[], ['bulk_start_error'=>$e->getMessage()])));
    }
}
if ($path === '/rules/toggle' && $method==='POST') { $table=($_POST['table']??'rules')==='allowlist_rules'?'allowlist_rules':'rules'; DB::statement("UPDATE $table SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END, updated_at=? WHERE id=?", [now(), (int)$_POST['id']]); redirect('/rules'); }
$threatIpClassifications = ['scanner','bruteforce','webshell_access','bot','direct_login','manual','unknown'];
if ($path === '/threat-ips/save' && $method === 'POST') {
    $ip = trim((string)($_POST['ip'] ?? ''));
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $classification = in_array($_POST['classification'] ?? '', $threatIpClassifications, true) ? $_POST['classification'] : 'unknown';
        $risk = in_array($_POST['risk'] ?? '', ['low','medium','high','critical'], true) ? $_POST['risk'] : 'medium';
        $notes = trim((string)($_POST['notes'] ?? ''));
        $existing = DB::first('SELECT id,hit_count FROM threat_ips WHERE ip=?', [$ip]);
        if ($existing) {
            DB::statement('UPDATE threat_ips SET classification=?,risk=?,notes=CASE WHEN ? = ? THEN notes ELSE ? END,last_seen_at=?,updated_at=? WHERE id=?', [$classification,$risk,$notes,'',$notes,now(),now(),$existing['id']]);
            $threatIpId = (int)$existing['id'];
        } else {
            $threatIpId = DB::insert('INSERT INTO threat_ips (ip,classification,risk,notes,hit_count,source,first_seen_at,last_seen_at,created_at,updated_at) VALUES (?,?,?,?,0,?,?,?,?,?)', [$ip,$classification,$risk,$notes,'manual',now(),now(),now(),now()]);
        }
        save_threat_ip_evidence($threatIpId, (int)($_POST['log_event_id'] ?? 0), $ip);
    }
    redirect('/threat-ips?ip='.urlencode($ip).'&saved=1');
}
if ($path === '/threat-ips/delete' && $method === 'POST') { $id=(int)$_POST['id']; $row=DB::first('SELECT firewall_status FROM threat_ips WHERE id=?',[$id]); if(($row['firewall_status']??'')!=='blocked'){ DB::statement('DELETE FROM threat_ip_evidence WHERE threat_ip_id=?',[$id]); DB::statement('DELETE FROM threat_ips WHERE id=?',[$id]); } redirect('/threat-ips'); }
if ($path === '/threat-ips/block' && $method === 'POST') {
    $ip = trim((string)($_POST['ip'] ?? ''));
    $existing = DB::first('SELECT id FROM threat_ips WHERE ip=?', [$ip]);
    if (!$existing && filter_var($ip, FILTER_VALIDATE_IP)) {
        $classification = in_array($_POST['classification'] ?? '', $threatIpClassifications, true) ? $_POST['classification'] : 'unknown';
        $risk = in_array($_POST['risk'] ?? '', ['low','medium','high','critical'], true) ? $_POST['risk'] : 'high';
        $id = DB::insert('INSERT INTO threat_ips (ip,classification,risk,notes,hit_count,source,first_seen_at,last_seen_at,created_at,updated_at) VALUES (?,?,?,?,0,?,?,?,?,?)', [$ip,$classification,$risk,trim((string)($_POST['notes']??'')),'firewall',now(),now(),now(),now()]);
        $existing = ['id'=>$id];
    }
    if ($existing && isset($_POST['classification'], $_POST['risk'])) {
        $classification = in_array($_POST['classification'], $threatIpClassifications, true) ? $_POST['classification'] : 'unknown';
        $risk = in_array($_POST['risk'], ['low','medium','high','critical'], true) ? $_POST['risk'] : 'high';
        $notes = trim((string)($_POST['notes'] ?? ''));
        DB::statement('UPDATE threat_ips SET classification=?,risk=?,notes=CASE WHEN ? = ? THEN notes ELSE ? END,last_seen_at=?,updated_at=? WHERE id=?', [$classification,$risk,$notes,'',$notes,now(),now(),$existing['id']]);
    }
    if ($existing) save_threat_ip_evidence((int)$existing['id'], (int)($_POST['log_event_id'] ?? 0), $ip);
    $result = 'block_failed'; $message = t('Firewall actions are disabled.'); $backend = '';
    if ($existing && config('guard.firewall_actions_enabled')) {
        try {
            $svc = new IpBlockService(); $before = $svc->status($ip); $after = $svc->block($ip); $backend = (string)($after['backend'] ?? $before['backend'] ?? '');
            $result = $before['blocked'] ? 'already_blocked' : 'blocked'; $message = '';
            DB::statement('UPDATE threat_ips SET firewall_status=?,firewall_error=NULL,blocked_at=COALESCE(blocked_at,?),updated_at=? WHERE id=?', ['blocked',now(),now(),$existing['id']]);
        } catch (Throwable $e) {
            $message = $e->getMessage();
            DB::statement('UPDATE threat_ips SET firewall_status=?,firewall_error=?,updated_at=? WHERE id=?', ['failed',$message,now(),$existing['id']]);
        }
    }
    redirect('/threat-ips?'.http_build_query(['ip'=>$ip,'block_result'=>$result,'block_message'=>$message,'block_backend'=>$backend]));
}
if ($path === '/threat-ips/abuse-report') {
    $ip = trim((string) ($_GET['ip'] ?? ''));
    if (!preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $ip)) redirect('/threat-ips');
    $threatIp = DB::first('SELECT * FROM threat_ips WHERE ip=?', [$ip]);
    $draft = (new AbuseReportService())->buildDraft($ip, $threatIp);
    echo view('threat_ips.abuse_report', ['draft' => $draft]);
    exit;
}
if ($path === '/trusted-ips/save' && $method === 'POST') {
    $ip = trim((string)($_POST['ip'] ?? ''));
    if ($ip !== '') {
        $label = (string)($_POST['label'] ?? ''); $notes = (string)($_POST['notes'] ?? '');
        $existing = DB::first('SELECT id FROM trusted_ips WHERE ip=?', [$ip]);
        if ($existing) DB::statement('UPDATE trusted_ips SET label=?,notes=?,updated_at=? WHERE id=?', [$label,$notes,now(),$existing['id']]);
        else DB::insert('INSERT INTO trusted_ips (ip,label,notes,created_at,updated_at) VALUES (?,?,?,?,?)', [$ip,$label,$notes,now(),now()]);
    }
    redirect('/trusted-ips');
}
if ($path === '/trusted-ips/delete' && $method === 'POST') { DB::statement('DELETE FROM trusted_ips WHERE id=?', [(int)$_POST['id']]); redirect('/trusted-ips'); }
if ($path === '/settings/telegram-test' && $method === 'POST') {
    $result = (new \App\Modules\Notifications\TelegramNotifier())->send((string)($_POST['message'] ?? 'Jura Server Guard: test notification.'));
    $_SESSION['telegram_test_result'] = $result;
    redirect('/settings');
}
if ($path === '/incidents/import' && $method === 'POST') {
    $dryRun = ($_POST['dry_run'] ?? '1') === '1';
    $upload = $_FILES['file'] ?? null;
    $importResult = null; $importError = null;
    if (!$upload || ($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        $importError = 'No file uploaded or upload failed.';
    } elseif ($upload['size'] > 10 * 1024 * 1024) {
        $importError = 'File too large (max 10 MB).';
    } else {
        $data = json_decode((string) file_get_contents($upload['tmp_name']), true);
        if (!is_array($data)) { $importError = 'File is not valid JSON.'; }
        else {
            $result = (new IncidentImportService())->import($data, $dryRun, $upload['name']);
            if (!$result['ok']) $importError = implode('; ', $result['errors']);
            elseif (!$dryRun) redirect('/incidents/' . $result['summary']['incident_id']);
            else $importResult = $result;
        }
    }
    echo view('incidents.import', ['result' => $importResult, 'error' => $importError]);
    exit;
}
if ($path === '/scan/active.json') { header('Content-Type: application/json'); echo json_encode(scan_active_context(), JSON_UNESCAPED_SLASHES); exit; }
if ($path === '/scan/cleanup-stale' && $method==='POST') { $ctx=scan_active_context(); if ($ctx['stale']) { DB::statement("UPDATE scan_runs SET status='completed', finished_at=?, error_text=?, last_heartbeat_at=?, progress_message=?, updated_at=? WHERE status='running' AND total_files_estimated > 0 AND files_scanned >= total_files_estimated", [now(), 'Marked completed by web cleanup: stale run had reached 100%', now(), 'Cleanup completed stale 100% scan', now()]); DB::statement("UPDATE scan_runs SET status='failed', finished_at=?, error_text=?, updated_at=? WHERE status='running'", [now(), 'Marked failed from web cleanup stale scan', now()]); (new ScanLock())->unlock(true); } redirect('/scan/active'); }
if ($path === '/scan/force-unlock' && $method==='POST') { $ctx=scan_active_context(); if ($ctx['stale']) (new ScanLock())->unlock(true); redirect('/scan/active'); }
if ($path === '/scan/stop' && $method==='POST') { $ctx=scan_active_context(); $pid=(int)($ctx['pid'] ?? 0); if ($pid > 0 && $ctx['pid_alive'] && function_exists('posix_kill')) @posix_kill($pid, SIGTERM); redirect('/scan/active'); }
if ($path === '/scan/start' && $method==='POST') { $profile=in_array($_POST['profile']??'fast',['fast','standard','deep'],true)?$_POST['profile']:'fast'; $scope=$_POST['scope']??'full'; $value=$_POST['value']??null; $ctx=scan_active_context(); if($ctx['running'] && !$ctx['stale']) redirect(back_url()); $maxSeconds = ($_POST['max_seconds'] ?? '') === '0' ? 0 : (int)($_POST['max_seconds'] ?? 0); start_background_scan($scope,$value,$profile,$maxSeconds); redirect(back_url()); }
if ($path === '/settings' && $method==='POST') { $keyCol=DB::quoteIdentifier('key'); foreach ($_POST['settings'] ?? [] as $k=>$v) { if(DB::first("SELECT id FROM settings WHERE $keyCol=?",[$k])) DB::statement("UPDATE settings SET value=?,updated_at=? WHERE $keyCol=?",[$v,now(),$k]); else DB::insert("INSERT INTO settings ($keyCol,value,created_at,updated_at) VALUES (?,?,?,?)",[$k,$v,now(),now()]); } redirect('/settings'); }
if ($path === '/findings/export.csv') { [$w,$p]=finding_filters(); send_csv('findings.csv', DB::select("SELECT f.id,f.risk,f.status,f.type,u.name user_name,s.name site_name,f.path,f.title,f.sha256,f.first_seen_at,f.last_seen_at FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id $w ORDER BY f.id DESC LIMIT 50000", $p)); }
if ($path === '/findings/export.json') {
    [$w,$p] = finding_filters();
    $rows = DB::select("SELECT f.*, s.name site_name, u.name user_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id $w ORDER BY f.id DESC LIMIT 5000", $p);
    $findings = array_map(function ($f) {
        return [
            'id' => (int) $f['id'], 'risk' => $f['risk'], 'status' => $f['status'], 'type' => $f['type'],
            'user' => $f['user_name'], 'site' => $f['site_name'], 'path' => $f['path'],
            'title' => $f['title'], 'description' => $f['description'], 'sha256' => $f['sha256'],
            'size' => $f['size'] !== null ? (int) $f['size'] : null, 'mtime' => $f['mtime'], 'owner' => $f['owner'], 'permissions' => $f['permissions'],
            'matched_signature_name' => $f['matched_signature_name'], 'matched_signature_source' => $f['matched_signature_source'],
            'matched_rules' => json_decode((string) $f['matched_rules'], true) ?: [],
            'signature_match_details' => json_decode((string) $f['signature_match_details'], true) ?: null,
            'first_seen_at' => $f['first_seen_at'], 'last_seen_at' => $f['last_seen_at'],
        ];
    }, $rows);
    send_json('findings-export.json', ['format' => 'jura-server-guard-findings-export', 'format_version' => '1.0', 'generated_at' => gmdate('c'), 'hostname' => @gethostname() ?: null, 'filters' => array_filter($_GET), 'count' => count($findings), 'findings' => $findings]);
}
if ($path === '/logs/export.csv') { [$w,$p]=log_filters(); send_csv('log_events.csv', DB::select("SELECT l.id,l.risk,l.event_type,u.name user_name,s.name site_name,l.ip,l.method,l.uri,l.status_code,l.user_agent,l.referer,l.created_at FROM log_events l LEFT JOIN sites s ON s.id=l.site_id LEFT JOIN users u ON u.id=s.server_user_id $w ORDER BY l.id DESC LIMIT 50000", $p)); }
if ($path === '/signatures/create') { echo view('signatures.form',['signature'=>null]); exit; }
if ($path === '/signatures/create-from-hash') {
    $sha = strtolower(trim((string)($_GET['sha256'] ?? '')));
    $filename = trim((string)($_GET['filename'] ?? ''));
    if (!preg_match('/^[a-f0-9]{64}$/', $sha)) redirect('/signatures/analyze');
    echo view('signatures.form', ['signature' => ['name' => 'Signature for ' . $filename, 'slug' => 'file-' . substr($sha, 0, 16), 'risk' => 'critical', 'type' => 'webshell', 'pattern_type' => 'hash', 'pattern_json' => json_encode(['sha256' => [$sha]]), 'description' => 'Created from uploaded file analysis: ' . $filename], 'preview' => '']);
    exit;
}
if ($path === '/signatures/analyze') {
    $analyzeResult = null; $analyzeError = null;
    if ($method === 'POST') {
        $filename = trim((string)($_POST['filename'] ?? ''));
        $content = null;
        $upload = $_FILES['file'] ?? null;
        if ($upload && ($upload['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_OK) {
            if ($upload['size'] > 5 * 1024 * 1024) $analyzeError = 'File too large (max 5 MB).';
            else { $content = file_get_contents($upload['tmp_name']); if ($filename === '') $filename = $upload['name']; }
        } elseif (trim((string)($_POST['content'] ?? '')) !== '') {
            $content = (string) $_POST['content'];
        } else {
            $analyzeError = 'Upload a file or paste its content.';
        }
        if ($content !== null && $analyzeError === null) {
            if ($filename === '') $filename = 'pasted-content.php';
            $sha256 = hash('sha256', $content);
            $meta = ['extension' => strtolower(pathinfo($filename, PATHINFO_EXTENSION)), 'sha256' => $sha256];
            $engine = new SignatureEngine();
            $matches = [];
            foreach ($engine->enabledSignatures() as $sig) {
                $match = $engine->match($sig, $filename, $filename, $meta, $content, '');
                if ($match) $matches[] = ['signature' => $match['signature'], 'matched' => $match['matched']];
            }
            $elsewhere = DB::select('SELECT fs.path, fs.is_missing, fs.last_seen_at, s.name site_name, u.name user_name FROM file_snapshots fs LEFT JOIN sites s ON s.id=fs.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE fs.sha256=? ORDER BY fs.last_seen_at DESC LIMIT 100', [$sha256]);
            $analyzeResult = ['filename' => $filename, 'sha256' => $sha256, 'size' => strlen($content), 'matches' => $matches, 'elsewhere' => $elsewhere, 'preview' => substr($content, 0, 4000)];
        }
    }
    echo view('signatures.analyze', ['result' => $analyzeResult, 'error' => $analyzeError]);
    exit;
}
if (preg_match('#^/signatures/(\d+)$#',$path,$m)) { $sig=DB::first('SELECT * FROM malware_signatures WHERE id=?',[(int)$m[1]]); echo view('signatures.show',['signature'=>$sig,'matches'=>DB::select('SELECT * FROM findings WHERE last_matched_signature_id=? OR matched_signature_name=? ORDER BY id DESC LIMIT 50',[(int)$m[1],$sig['name']??''])]); exit; }
if ($path === '/signatures/sweep' && $method === 'POST') {
    @set_time_limit(300);
    $id = (int) ($_POST['id'] ?? 0);
    try {
        $result = (new \App\Modules\Scanner\SignatureSweepService())->sweep($id);
        redirect('/signatures/' . $id . '?' . http_build_query(['sweep_sites' => $result['sites_scanned'], 'sweep_files' => $result['files_scanned'], 'sweep_matches' => count($result['finding_ids'])]));
    } catch (Throwable $e) {
        redirect('/signatures/' . $id . '?' . http_build_query(['sweep_error' => $e->getMessage()]));
    }
}
if (preg_match('#^/findings/(\d+)$#',$path,$m)) {
    $f=DB::first('SELECT f.*,s.name site_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id WHERE f.id=?',[(int)$m[1]]);
    $elsewhere = (!empty($f['sha256'])) ? DB::select('SELECT fs.path, fs.is_missing, fs.last_seen_at, s.name site_name, u.name user_name FROM file_snapshots fs LEFT JOIN sites s ON s.id=fs.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE fs.sha256=? AND fs.path<>? ORDER BY fs.last_seen_at DESC LIMIT 100', [$f['sha256'], $f['path']]) : [];
    echo view('findings.show',['finding'=>$f,'events'=>DB::select('SELECT * FROM log_events WHERE raw_line LIKE ? OR uri LIKE ? ORDER BY id DESC LIMIT 50',['%'.basename($f['path']??'').'%','%'.basename($f['path']??'').'%']),'filePreview'=>safe_finding_preview($f),'elsewhere'=>$elsewhere,'aiSuggestions'=>DB::select('SELECT * FROM signature_suggestions WHERE finding_id=? ORDER BY id DESC',[(int)$m[1]])]);
    exit;
}
if (preg_match('#^/incidents/(\d+)$#',$path,$m)) {
    $incident = DB::first('SELECT * FROM incidents WHERE id=?', [(int)$m[1]]);
    if (!$incident) { echo view('dashboard.404'); exit; }
    $threatIps = DB::select('SELECT t.* FROM threat_ips t JOIN incident_threat_ip_links l ON l.threat_ip_id=t.id WHERE l.incident_id=? ORDER BY t.risk DESC, t.ip', [$incident['id']]);
    $signatures = DB::select('SELECT ms.* FROM malware_signatures ms JOIN incident_signature_links l ON l.signature_id=ms.id WHERE l.incident_id=? ORDER BY ms.enabled DESC, ms.risk DESC, ms.name', [$incident['id']]);
    $fileIocs = DB::select('SELECT f.* FROM incident_file_iocs f JOIN incident_file_ioc_links l ON l.file_ioc_id=f.id WHERE l.incident_id=? ORDER BY f.risk DESC, f.sha256', [$incident['id']]);
    $hashes = array_values(array_unique(array_column($fileIocs, 'sha256')));
    $seenByHash = [];
    if ($hashes) {
        $placeholders = implode(',', array_fill(0, count($hashes), '?'));
        foreach (DB::select("SELECT fs.sha256, fs.path, fs.is_missing, fs.last_seen_at, s.name site_name, u.name user_name FROM file_snapshots fs LEFT JOIN sites s ON s.id=fs.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE fs.sha256 IN ($placeholders) ORDER BY fs.last_seen_at DESC", $hashes) as $row) {
            $seenByHash[$row['sha256']][] = $row;
        }
    }
    $affectedAssets = json_decode((string)($incident['affected_assets_json'] ?? '{}'), true) ?: [];
    $allAssetNames = array_values(array_unique(array_merge([], ...array_values(array_map(fn($v)=>is_array($v)?$v:[], $affectedAssets)))));
    $siteByName = [];
    if ($allAssetNames) {
        $placeholders = implode(',', array_fill(0, count($allAssetNames), '?'));
        foreach (DB::select("SELECT s.id, s.name, s.path, u.name user_name FROM sites s LEFT JOIN users u ON u.id=s.server_user_id WHERE s.name IN ($placeholders)", $allAssetNames) as $row) {
            $siteByName[$row['name']] = $row;
        }
    }
    echo view('incidents.show', [
        'incident' => $incident,
        'threatIps' => $threatIps,
        'signatures' => $signatures,
        'fileIocs' => $fileIocs,
        'seenByHash' => $seenByHash,
        'timeline' => json_decode((string)($incident['timeline_json'] ?? '{}'), true) ?: [],
        'affectedAssets' => $affectedAssets,
        'siteByName' => $siteByName,
        'pathIndicators' => json_decode((string)($incident['path_indicators_json'] ?? '[]'), true) ?: [],
        'excludedIps' => json_decode((string)($incident['excluded_ips_json'] ?? '[]'), true) ?: [],
        'responseActions' => json_decode((string)($incident['response_actions_json'] ?? '{}'), true) ?: [],
    ]);
    exit;
}
if ($path === '/search') {
    $q = trim((string)($_GET['q'] ?? ''));
    $isHash = (bool) preg_match('/^[a-f0-9]{64}$/i', $q);
    $isIp = (bool) preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $q);
    $results = ['q' => $q, 'is_hash' => $isHash, 'is_ip' => $isIp];
    if ($q !== '') {
        $like = '%' . $q . '%';
        if ($isHash) {
            $hash = strtolower($q);
            $results['file_snapshots'] = DB::select('SELECT fs.*, s.name site_name, u.name user_name FROM file_snapshots fs LEFT JOIN sites s ON s.id=fs.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE fs.sha256=? ORDER BY fs.last_seen_at DESC LIMIT 100', [$hash]);
            $results['findings'] = DB::select('SELECT f.*, s.name site_name, u.name user_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE f.sha256=? ORDER BY f.id DESC LIMIT 100', [$hash]);
            $results['quarantine'] = DB::select('SELECT * FROM quarantine_items WHERE sha256=? ORDER BY id DESC LIMIT 100', [$hash]);
            $results['signatures'] = DB::select("SELECT * FROM malware_signatures WHERE pattern_type='hash' AND pattern_json LIKE ? ORDER BY id DESC LIMIT 100", ['%' . $hash . '%']);
            $results['file_iocs'] = DB::select('SELECT fi.*, GROUP_CONCAT(i.title) incident_titles FROM incident_file_iocs fi LEFT JOIN incident_file_ioc_links l ON l.file_ioc_id=fi.id LEFT JOIN incidents i ON i.id=l.incident_id WHERE fi.sha256=? GROUP BY fi.id ORDER BY fi.id DESC LIMIT 100', [$hash]);
        } elseif ($isIp) {
            $results['threat_ips'] = DB::select('SELECT * FROM threat_ips WHERE ip=?', [$q]);
            $results['trusted_ips'] = DB::select('SELECT * FROM trusted_ips WHERE ip=?', [$q]);
            $results['logs'] = DB::select('SELECT l.*, s.name site_name FROM log_events l LEFT JOIN sites s ON s.id=l.site_id WHERE l.ip=? ORDER BY l.id DESC LIMIT 100', [$q]);
        } else {
            $results['file_snapshots'] = DB::select('SELECT fs.*, s.name site_name, u.name user_name FROM file_snapshots fs LEFT JOIN sites s ON s.id=fs.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE fs.path LIKE ? ORDER BY fs.last_seen_at DESC LIMIT 100', [$like]);
            $results['findings'] = DB::select('SELECT f.*, s.name site_name, u.name user_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE f.path LIKE ? OR f.title LIKE ? ORDER BY f.id DESC LIMIT 100', [$like, $like]);
            $results['quarantine'] = DB::select('SELECT * FROM quarantine_items WHERE original_path LIKE ? ORDER BY id DESC LIMIT 100', [$like]);
            $results['logs'] = DB::select('SELECT l.*, s.name site_name FROM log_events l LEFT JOIN sites s ON s.id=l.site_id WHERE l.uri LIKE ? ORDER BY l.id DESC LIMIT 100', [$like]);
            $results['signatures'] = DB::select('SELECT * FROM malware_signatures WHERE name LIKE ? OR description LIKE ? OR pattern_json LIKE ? ORDER BY id DESC LIMIT 100', [$like, $like, $like]);
            $results['incidents'] = DB::select('SELECT * FROM incidents WHERE title LIKE ? OR summary LIKE ? ORDER BY id DESC LIMIT 100', [$like, $like]);
            $results['file_iocs'] = DB::select('SELECT fi.*, GROUP_CONCAT(i.title) incident_titles FROM incident_file_iocs fi LEFT JOIN incident_file_ioc_links l ON l.file_ioc_id=fi.id LEFT JOIN incidents i ON i.id=l.incident_id WHERE fi.names_json LIKE ? GROUP BY fi.id ORDER BY fi.id DESC LIMIT 100', [$like]);
        }
    }
    echo view('search.index', $results);
    exit;
}
$data = match ($path) {
 '/scan/active' => ['scan.active', ['ctx'=>scan_active_context()]],
 '/' => ['dashboard.index', ['activeScan'=>scan_active_context()['run'],'activeLock'=>scan_active_context()['lock'],'last'=>DB::first('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1'),'users'=>DB::first('SELECT COUNT(*) c FROM users')['c']??0,'sites'=>DB::first('SELECT COUNT(*) c FROM sites')['c']??0,'new'=>DB::first("SELECT COUNT(*) c FROM findings WHERE status='new'")['c']??0,'crit'=>DB::first("SELECT COUNT(*) c FROM findings WHERE risk='critical' AND status='new'")['c']??0,'high'=>DB::first("SELECT COUNT(*) c FROM findings WHERE risk='high' AND status='new'")['c']??0,'q'=>DB::first("SELECT COUNT(*) c FROM quarantine_items WHERE status='quarantined'")['c']??0,'logs'=>DB::select('SELECT l.*, s.name site_name FROM log_events l LEFT JOIN sites s ON s.id=l.site_id ORDER BY l.created_at DESC, l.id DESC LIMIT 10'),'threatIps'=>(function(){ $ips=[]; foreach(DB::select('SELECT ip,classification,risk FROM threat_ips') as $r) $ips[$r['ip']]=$r; return $ips; })(),'scanRuns'=>DB::select('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 10')]],
 '/users' => ['users.index',['scanCtx'=>scan_active_context(),'users'=>DB::select('SELECT u.*, COUNT(DISTINCT s.id) sites_count, COUNT(f.id) findings_count, MAX(s.last_scan_at) last_scan_at FROM users u LEFT JOIN sites s ON s.server_user_id=u.id LEFT JOIN findings f ON f.site_id=s.id GROUP BY u.id ORDER BY u.name')]],
 '/sites' => ['sites.index',['scanCtx'=>scan_active_context(),'sites'=>DB::select('SELECT s.*, u.name user_name, COUNT(f.id) findings_count, MAX(CASE f.risk WHEN "critical" THEN 4 WHEN "high" THEN 3 WHEN "medium" THEN 2 ELSE 1 END) risk_score FROM sites s LEFT JOIN users u ON u.id=s.server_user_id LEFT JOIN findings f ON f.site_id=s.id AND f.status="new" GROUP BY s.id ORDER BY s.path')]],
 '/findings' => ['findings.index',(function(){ [$w,$p]=finding_filters(); $total=(int)(DB::first('SELECT COUNT(*) c FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id '.$w, $p)['c'] ?? 0); $pagination=findings_pagination($total); return ['findings'=>DB::select('SELECT f.*, s.name site_name, u.name user_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id '.$w.' ORDER BY CASE risk WHEN "critical" THEN 1 WHEN "high" THEN 2 WHEN "medium" THEN 3 ELSE 4 END, f.id DESC'.$pagination['sql'],$p), 'total'=>$total, 'pagination'=>$pagination, 'user_names'=>array_column(DB::select('SELECT DISTINCT name FROM users ORDER BY name'), 'name'), 'types'=>array_column(DB::select('SELECT DISTINCT type FROM findings WHERE type IS NOT NULL AND type<>? ORDER BY type', ['']), 'type')]; })()],
 '/logs' => ['logs.index',(function(){ [$w,$p]=log_filters(); $ips=[]; foreach(DB::select('SELECT ip,classification,risk FROM threat_ips') as $r) $ips[$r['ip']]=$r; return ['events'=>DB::select('SELECT l.*, s.name site_name, u.name user_name FROM log_events l LEFT JOIN sites s ON s.id=l.site_id LEFT JOIN users u ON u.id=s.server_user_id '.$w.' ORDER BY l.created_at DESC, l.id DESC LIMIT 1000',$p),'threatIps'=>$ips]; })()],
 '/file-changes' => ['file-changes.index',(function(){ [$w,$p]=file_change_filters(); return ['changes'=>DB::select('SELECT fs.*, s.name site_name FROM file_snapshots fs LEFT JOIN sites s ON s.id=fs.site_id '.$w.' ORDER BY COALESCE(fs.last_changed_at,fs.first_seen_at,fs.updated_at) DESC LIMIT 1000',$p), 'lastRuns'=>DB::select('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 10')]; })()],
 '/quarantine' => ['quarantine.index',['items'=>DB::select('SELECT * FROM quarantine_items ORDER BY id DESC')]],
 '/signatures' => ['signatures.index',(function(){ [$w,$p]=signature_filters(); return ['signatures'=>DB::select('SELECT * FROM malware_signatures '.$w.' ORDER BY enabled DESC,risk DESC,name',$p)]; })()],
 '/rules' => ['rules.index',['rules'=>DB::select('SELECT * FROM rules ORDER BY enabled DESC,risk DESC,name'),'allow'=>DB::select('SELECT * FROM allowlist_rules ORDER BY enabled DESC,name')]],
 '/threat-ips' => ['threat_ips.index',(function() use ($threatIpClassifications) { $ip=trim((string)($_GET['ip']??'')); $existing=$ip!==''?DB::first('SELECT * FROM threat_ips WHERE ip=?',[$ip]):null; $eventId=(int)($_GET['event_id']??0); $event=$eventId?log_event_with_site($eventId,$ip):null; $rows=DB::select('SELECT * FROM threat_ips ORDER BY updated_at DESC'); $evidence=[]; foreach(DB::select('SELECT * FROM threat_ip_evidence ORDER BY detected_at DESC,id DESC') as $e) $evidence[(int)$e['threat_ip_id']][]=$e; return ['ips'=>$rows,'classifications'=>$threatIpClassifications,'prefillIp'=>$ip,'existingIp'=>$existing,'contextEvent'=>$event,'evidenceByIp'=>$evidence]; })()],
 '/trusted-ips' => ['trusted_ips.index',['ips'=>DB::select('SELECT * FROM trusted_ips ORDER BY updated_at DESC')]],
 '/incidents' => ['incidents.index',['incidents'=>DB::select("SELECT i.*, (SELECT COUNT(*) FROM incident_threat_ip_links l WHERE l.incident_id=i.id) threat_ips_count, (SELECT COUNT(*) FROM incident_signature_links l WHERE l.incident_id=i.id) signatures_count, (SELECT COUNT(*) FROM incident_file_ioc_links l WHERE l.incident_id=i.id) file_iocs_count FROM incidents i ORDER BY i.imported_at DESC")]],
 '/incidents/import' => ['incidents.import',['result'=>null,'error'=>null]],
 '/settings' => ['settings.index',['settings'=>DB::select('SELECT * FROM settings ORDER BY '.DB::quoteIdentifier('key')),'telegramTestResult'=>(function(){ $r=$_SESSION['telegram_test_result']??null; unset($_SESSION['telegram_test_result']); return $r; })()]],
 '/backups' => ['backups.index',(function(){ $svc=new IspmanagerBackupService(); $path=$_GET['path']??''; $date=$_GET['date']??''; return ['service'=>$svc,'detect'=>$svc->detectTools(),'users'=>$svc->users(),'backups'=>$svc->backups($_GET['user']??null),'found'=>$path?$svc->findFile($path,$date?:null):[],'searchPath'=>$path,'date'=>$date,'preview'=>($path&&$date)?$svc->preview($path,$date):null,'diff'=>($path&&$date)?$svc->diff($path,$date):null]; })()],
 default => ['dashboard.404', []],
};
echo view($data[0], $data[1]);
