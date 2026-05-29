<?php
require dirname(__DIR__).'/vendor/autoload.php';
use App\Support\Auth; use App\Support\DB; use App\Modules\Quarantine\QuarantineService;
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
try { DB::pdo(); } catch (Throwable $e) { echo 'Database not initialized. Run php artisan migrate.'; exit; }
if ($path === '/login' && $method === 'POST') { Auth::attempt($_POST['email'] ?? '', $_POST['password'] ?? '') ? redirect('/') : print view('auth.login', ['error'=>'Invalid credentials']); exit; }
if ($path === '/login') { echo view('auth.login'); exit; }
if ($path === '/logout') { Auth::logout(); redirect('/login'); }
Auth::require();
if ($path === '/finding/ignore' && $method==='POST') { DB::statement('UPDATE findings SET status=?, updated_at=? WHERE id=?', ['ignored', now(), (int)$_POST['id']]); redirect('/findings/'.(int)$_POST['id']); }
if ($path === '/finding/allowlist' && $method==='POST') { $f=DB::first('SELECT * FROM findings WHERE id=?',[(int)$_POST['id']]); if($f) DB::insert('INSERT INTO allowlist_rules (name,path_pattern,sha256,reason,enabled,created_at,updated_at) VALUES (?,?,?,?,1,?,?)',['Web allowlist '.$f['id'],$f['path'],$f['sha256'],'Added from finding page',now(),now()]); redirect('/rules'); }
if ($path === '/finding/quarantine' && $method==='POST' && config('guard.web_actions_enabled')) { (new QuarantineService())->quarantine((int)$_POST['id'], 'Web panel quarantine'); redirect('/quarantine'); }
if ($path === '/quarantine/restore' && $method==='POST' && config('guard.web_actions_enabled')) { (new QuarantineService())->restore((int)$_POST['id']); redirect('/quarantine'); }
if ($path === '/rules/toggle' && $method==='POST') { $table=($_POST['table']??'rules')==='allowlist_rules'?'allowlist_rules':'rules'; DB::statement("UPDATE $table SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END, updated_at=? WHERE id=?", [now(), (int)$_POST['id']]); redirect('/rules'); }
if ($path === '/settings' && $method==='POST') { foreach ($_POST['settings'] ?? [] as $k=>$v) { if(DB::first('SELECT id FROM settings WHERE key=?',[$k])) DB::statement('UPDATE settings SET value=?,updated_at=? WHERE key=?',[$v,now(),$k]); else DB::insert('INSERT INTO settings (key,value,created_at,updated_at) VALUES (?,?,?,?)',[$k,$v,now(),now()]); } redirect('/settings'); }
if (preg_match('#^/findings/(\d+)$#',$path,$m)) { $f=DB::first('SELECT f.*,s.name site_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id WHERE f.id=?',[(int)$m[1]]); echo view('findings.show',['finding'=>$f,'events'=>DB::select('SELECT * FROM log_events WHERE raw_line LIKE ? OR uri LIKE ? ORDER BY id DESC LIMIT 50',['%'.basename($f['path']??'').'%','%'.basename($f['path']??'').'%']),'preview'=>($f&&is_readable($f['path']))?file_get_contents($f['path'],false,null,0,min(config('guard.max_file_read_bytes'),65536)):'']); exit; }
$data = match ($path) {
 '/' => ['dashboard.index', ['last'=>DB::first('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1'),'users'=>DB::first('SELECT COUNT(*) c FROM users')['c']??0,'sites'=>DB::first('SELECT COUNT(*) c FROM sites')['c']??0,'new'=>DB::first("SELECT COUNT(*) c FROM findings WHERE status='new'")['c']??0,'crit'=>DB::first("SELECT COUNT(*) c FROM findings WHERE risk='critical' AND status='new'")['c']??0,'high'=>DB::first("SELECT COUNT(*) c FROM findings WHERE risk='high' AND status='new'")['c']??0,'q'=>DB::first("SELECT COUNT(*) c FROM quarantine_items WHERE status='quarantined'")['c']??0,'logs'=>DB::select('SELECT * FROM log_events ORDER BY id DESC LIMIT 10')]],
 '/users' => ['users.index',['users'=>DB::select('SELECT u.*, COUNT(DISTINCT s.id) sites_count, COUNT(f.id) findings_count, MAX(s.last_scan_at) last_scan_at FROM users u LEFT JOIN sites s ON s.server_user_id=u.id LEFT JOIN findings f ON f.site_id=s.id GROUP BY u.id ORDER BY u.name')]],
 '/sites' => ['sites.index',['sites'=>DB::select('SELECT s.*, u.name user_name, COUNT(f.id) findings_count, MAX(CASE f.risk WHEN "critical" THEN 4 WHEN "high" THEN 3 WHEN "medium" THEN 2 ELSE 1 END) risk_score FROM sites s LEFT JOIN users u ON u.id=s.server_user_id LEFT JOIN findings f ON f.site_id=s.id AND f.status="new" GROUP BY s.id ORDER BY s.path')]],
 '/findings' => ['findings.index',['findings'=>DB::select('SELECT f.*, s.name site_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id ORDER BY CASE risk WHEN "critical" THEN 1 WHEN "high" THEN 2 WHEN "medium" THEN 3 ELSE 4 END, id DESC LIMIT 500')]],
 '/logs' => ['logs.index',['events'=>DB::select('SELECT * FROM log_events WHERE (?="" OR ip=?) AND (?="" OR uri LIKE ?) AND (?="" OR risk=?) ORDER BY id DESC LIMIT 1000',[$_GET['ip']??'',$_GET['ip']??'',$_GET['uri']??'','%'.($_GET['uri']??'').'%',$_GET['risk']??'',$_GET['risk']??''])]],
 '/quarantine' => ['quarantine.index',['items'=>DB::select('SELECT * FROM quarantine_items ORDER BY id DESC')]],
 '/rules' => ['rules.index',['rules'=>DB::select('SELECT * FROM rules ORDER BY enabled DESC,risk DESC,name'),'allow'=>DB::select('SELECT * FROM allowlist_rules ORDER BY enabled DESC,name')]],
 '/settings' => ['settings.index',['settings'=>DB::select('SELECT * FROM settings ORDER BY key')]],
 default => ['dashboard.404', []],
};
echo view($data[0], $data[1]);
