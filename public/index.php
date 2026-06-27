<?php
function utc_timestamp(string $timestamp): int { return strtotime($timestamp . ' UTC') ?: strtotime($timestamp) ?: time(); }
require dirname(__DIR__).'/vendor/autoload.php';
use App\Support\Auth; use App\Support\DB; use App\Support\ScanLock; use App\Modules\Quarantine\QuarantineService; use App\Modules\Scanner\ScannerService; use App\Modules\Backups\IspmanagerBackupService;
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
try { DB::pdo(); } catch (Throwable $e) { echo 'Database not initialized. Run php artisan migrate.'; exit; }
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
function back_url(): string { return $_SERVER['HTTP_REFERER'] ?? '/'; }

function send_csv(string $filename, array $rows): void {
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="'.$filename.'"');
    $out = fopen('php://output', 'w');
    if ($rows) { fputcsv($out, array_keys($rows[0])); foreach ($rows as $row) fputcsv($out, $row); }
    fclose($out); exit;
}
function finding_filters(): array {
    $where=[]; $params=[];
    foreach (['risk'=>'f.risk','status'=>'f.status','type'=>'f.type'] as $key=>$col) if (($_GET[$key]??'')!=='') { $where[]="$col=?"; $params[]=$_GET[$key]; }
    if (($_GET['user']??'')!=='') { $where[]='u.name=?'; $params[]=$_GET['user']; }
    if (($_GET['site']??'')!=='') { $where[]='s.name=?'; $params[]=$_GET['site']; }
    if (($_GET['path']??'')!=='') { $where[]='f.path LIKE ?'; $params[]='%'.$_GET['path'].'%'; }
    if (($_GET['date_from']??'')!=='') { $where[]='f.last_seen_at >= ?'; $params[]=$_GET['date_from'].' 00:00:00'; }
    if (($_GET['date_to']??'')!=='') { $where[]='f.last_seen_at <= ?'; $params[]=$_GET['date_to'].' 23:59:59'; }
    return [$where ? 'WHERE '.implode(' AND ', $where) : '', $params];
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
function log_filters(): array {
    $where=[]; $params=[];
    foreach (['risk'=>'l.risk','type'=>'l.event_type','ip'=>'l.ip'] as $key=>$col) if (($_GET[$key]??'')!=='') { $where[]="$col=?"; $params[]=$_GET[$key]; }
    if (($_GET['uri']??'')!=='') { $where[]='l.uri LIKE ?'; $params[]='%'.$_GET['uri'].'%'; }
    if (($_GET['site']??'')!=='') { $where[]='s.name=?'; $params[]=$_GET['site']; }
    if (($_GET['date_from']??'')!=='') { $where[]='l.created_at >= ?'; $params[]=$_GET['date_from'].' 00:00:00'; }
    if (($_GET['date_to']??'')!=='') { $where[]='l.created_at <= ?'; $params[]=$_GET['date_to'].' 23:59:59'; }
    return [$where ? 'WHERE '.implode(' AND ', $where) : '', $params];
}

if ($path === '/finding/ignore' && $method==='POST') { DB::statement('UPDATE findings SET status=?, updated_at=? WHERE id=?', ['ignored', now(), (int)$_POST['id']]); redirect('/findings/'.(int)$_POST['id']); }
if ($path === '/finding/allowlist' && $method==='POST') { $f=DB::first('SELECT * FROM findings WHERE id=?',[(int)$_POST['id']]); if($f) DB::insert('INSERT INTO allowlist_rules (name,path_pattern,sha256,reason,enabled,created_at,updated_at) VALUES (?,?,?,?,1,?,?)',['Web allowlist '.$f['id'],$f['path'],$f['sha256'],'Added from finding page',now(),now()]); redirect('/rules'); }
if ($path === '/finding/quarantine' && $method==='POST' && config('guard.web_actions_enabled')) { (new QuarantineService())->quarantine((int)$_POST['id'], 'Web panel quarantine'); redirect('/quarantine'); }
if ($path === '/quarantine/restore' && $method==='POST' && config('guard.web_actions_enabled')) { (new QuarantineService())->restore((int)$_POST['id']); redirect('/quarantine'); }
if ($path === '/rules/toggle' && $method==='POST') { $table=($_POST['table']??'rules')==='allowlist_rules'?'allowlist_rules':'rules'; DB::statement("UPDATE $table SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END, updated_at=? WHERE id=?", [now(), (int)$_POST['id']]); redirect('/rules'); }
if ($path === '/scan/active.json') { header('Content-Type: application/json'); echo json_encode(scan_active_context(), JSON_UNESCAPED_SLASHES); exit; }
if ($path === '/scan/cleanup-stale' && $method==='POST') { $ctx=scan_active_context(); if ($ctx['stale']) { DB::statement("UPDATE scan_runs SET status='completed', finished_at=?, error_text=?, last_heartbeat_at=?, progress_message=?, updated_at=? WHERE status='running' AND total_files_estimated > 0 AND files_scanned >= total_files_estimated", [now(), 'Marked completed by web cleanup: stale run had reached 100%', now(), 'Cleanup completed stale 100% scan', now()]); DB::statement("UPDATE scan_runs SET status='failed', finished_at=?, error_text=?, updated_at=? WHERE status='running'", [now(), 'Marked failed from web cleanup stale scan', now()]); (new ScanLock())->unlock(true); } redirect('/scan/active'); }
if ($path === '/scan/force-unlock' && $method==='POST') { $ctx=scan_active_context(); if ($ctx['stale']) (new ScanLock())->unlock(true); redirect('/scan/active'); }
if ($path === '/scan/stop' && $method==='POST') { $ctx=scan_active_context(); $pid=(int)($ctx['pid'] ?? 0); if ($pid > 0 && $ctx['pid_alive'] && function_exists('posix_kill')) @posix_kill($pid, SIGTERM); redirect('/scan/active'); }
if ($path === '/scan/start' && $method==='POST') { $profile=in_array($_POST['profile']??'fast',['fast','standard','deep'],true)?$_POST['profile']:'fast'; $scope=$_POST['scope']??'full'; $value=$_POST['value']??null; $ctx=scan_active_context(); if($ctx['running'] && !$ctx['stale']) redirect(back_url()); $maxSeconds = ($_POST['max_seconds'] ?? '') === '0' ? 0 : (int)($_POST['max_seconds'] ?? 0); start_background_scan($scope,$value,$profile,$maxSeconds); redirect(back_url()); }
if ($path === '/settings' && $method==='POST') { $keyCol=DB::quoteIdentifier('key'); foreach ($_POST['settings'] ?? [] as $k=>$v) { if(DB::first("SELECT id FROM settings WHERE $keyCol=?",[$k])) DB::statement("UPDATE settings SET value=?,updated_at=? WHERE $keyCol=?",[$v,now(),$k]); else DB::insert("INSERT INTO settings ($keyCol,value,created_at,updated_at) VALUES (?,?,?,?)",[$k,$v,now(),now()]); } redirect('/settings'); }
if ($path === '/findings/export.csv') { [$w,$p]=finding_filters(); send_csv('findings.csv', DB::select("SELECT f.id,f.risk,f.status,f.type,u.name user_name,s.name site_name,f.path,f.title,f.sha256,f.first_seen_at,f.last_seen_at FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id $w ORDER BY f.id DESC LIMIT 50000", $p)); }
if ($path === '/logs/export.csv') { [$w,$p]=log_filters(); send_csv('log_events.csv', DB::select("SELECT l.id,l.risk,l.event_type,u.name user_name,s.name site_name,l.ip,l.method,l.uri,l.status_code,l.user_agent,l.referer,l.created_at FROM log_events l LEFT JOIN sites s ON s.id=l.site_id LEFT JOIN users u ON u.id=s.server_user_id $w ORDER BY l.id DESC LIMIT 50000", $p)); }
if (preg_match('#^/findings/(\d+)$#',$path,$m)) { $f=DB::first('SELECT f.*,s.name site_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id WHERE f.id=?',[(int)$m[1]]); echo view('findings.show',['finding'=>$f,'events'=>DB::select('SELECT * FROM log_events WHERE raw_line LIKE ? OR uri LIKE ? ORDER BY id DESC LIMIT 50',['%'.basename($f['path']??'').'%','%'.basename($f['path']??'').'%']),'preview'=>($f&&is_readable($f['path']))?file_get_contents($f['path'],false,null,0,min(config('guard.max_file_read_bytes'),65536)):'']); exit; }
$data = match ($path) {
 '/scan/active' => ['scan.active', ['ctx'=>scan_active_context()]],
 '/' => ['dashboard.index', ['activeScan'=>scan_active_context()['run'],'activeLock'=>scan_active_context()['lock'],'last'=>DB::first('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1'),'users'=>DB::first('SELECT COUNT(*) c FROM users')['c']??0,'sites'=>DB::first('SELECT COUNT(*) c FROM sites')['c']??0,'new'=>DB::first("SELECT COUNT(*) c FROM findings WHERE status='new'")['c']??0,'crit'=>DB::first("SELECT COUNT(*) c FROM findings WHERE risk='critical' AND status='new'")['c']??0,'high'=>DB::first("SELECT COUNT(*) c FROM findings WHERE risk='high' AND status='new'")['c']??0,'q'=>DB::first("SELECT COUNT(*) c FROM quarantine_items WHERE status='quarantined'")['c']??0,'logs'=>DB::select('SELECT l.*, s.name site_name FROM log_events l LEFT JOIN sites s ON s.id=l.site_id ORDER BY l.id DESC LIMIT 10'),'scanRuns'=>DB::select('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 10')]],
 '/users' => ['users.index',['scanCtx'=>scan_active_context(),'users'=>DB::select('SELECT u.*, COUNT(DISTINCT s.id) sites_count, COUNT(f.id) findings_count, MAX(s.last_scan_at) last_scan_at FROM users u LEFT JOIN sites s ON s.server_user_id=u.id LEFT JOIN findings f ON f.site_id=s.id GROUP BY u.id ORDER BY u.name')]],
 '/sites' => ['sites.index',['scanCtx'=>scan_active_context(),'sites'=>DB::select('SELECT s.*, u.name user_name, COUNT(f.id) findings_count, MAX(CASE f.risk WHEN "critical" THEN 4 WHEN "high" THEN 3 WHEN "medium" THEN 2 ELSE 1 END) risk_score FROM sites s LEFT JOIN users u ON u.id=s.server_user_id LEFT JOIN findings f ON f.site_id=s.id AND f.status="new" GROUP BY s.id ORDER BY s.path')]],
 '/findings' => ['findings.index',(function(){ [$w,$p]=finding_filters(); return ['findings'=>DB::select('SELECT f.*, s.name site_name, u.name user_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id '.$w.' ORDER BY CASE risk WHEN "critical" THEN 1 WHEN "high" THEN 2 WHEN "medium" THEN 3 ELSE 4 END, f.id DESC LIMIT 500',$p)]; })()],
 '/logs' => ['logs.index',(function(){ [$w,$p]=log_filters(); return ['events'=>DB::select('SELECT l.*, s.name site_name, u.name user_name FROM log_events l LEFT JOIN sites s ON s.id=l.site_id LEFT JOIN users u ON u.id=s.server_user_id '.$w.' ORDER BY l.id DESC LIMIT 1000',$p)]; })()],
 '/file-changes' => ['file-changes.index',(function(){ [$w,$p]=file_change_filters(); return ['changes'=>DB::select('SELECT fs.*, s.name site_name FROM file_snapshots fs LEFT JOIN sites s ON s.id=fs.site_id '.$w.' ORDER BY COALESCE(fs.last_changed_at,fs.first_seen_at,fs.updated_at) DESC LIMIT 1000',$p), 'lastRuns'=>DB::select('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 10')]; })()],
 '/quarantine' => ['quarantine.index',['items'=>DB::select('SELECT * FROM quarantine_items ORDER BY id DESC')]],
 '/rules' => ['rules.index',['rules'=>DB::select('SELECT * FROM rules ORDER BY enabled DESC,risk DESC,name'),'allow'=>DB::select('SELECT * FROM allowlist_rules ORDER BY enabled DESC,name')]],
 '/settings' => ['settings.index',['settings'=>DB::select('SELECT * FROM settings ORDER BY '.DB::quoteIdentifier('key'))]],
 '/backups' => ['backups.index',(function(){ $svc=new IspmanagerBackupService(); $path=$_GET['path']??''; $date=$_GET['date']??''; return ['service'=>$svc,'detect'=>$svc->detectTools(),'users'=>$svc->users(),'backups'=>$svc->backups($_GET['user']??null),'found'=>$path?$svc->findFile($path,$date?:null):[],'searchPath'=>$path,'date'=>$date,'preview'=>($path&&$date)?$svc->preview($path,$date):null,'diff'=>($path&&$date)?$svc->diff($path,$date):null]; })()],
 default => ['dashboard.404', []],
};
echo view($data[0], $data[1]);
