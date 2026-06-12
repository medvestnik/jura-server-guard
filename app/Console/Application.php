<?php
namespace App\Console;

use App\Modules\Backups\IspmanagerBackupService;
use App\Modules\LogAnalyzer\LogAnalyzerService;
use App\Modules\Quarantine\QuarantineService;
use App\Modules\Rules\RuleRepository;
use App\Modules\Scanner\ScannerService;
use App\Support\DB;
use App\Support\ScanLock;

class Application
{
    public function run(array $argv): int
    {
        $cmd = $argv[1] ?? 'list';
        try {
            return match ($cmd) {
                'serve' => $this->serve($argv), 'migrate' => $this->migrate(), 'guard:seed-rules' => $this->seedRules(), 'guard:create-admin' => $this->createAdmin($argv[2] ?? env_value('JURA_ADMIN_EMAIL','admin@example.com'), $argv[3] ?? bin2hex(random_bytes(12))),
                'guard:scan' => $this->scan('full', null, $argv), 'guard:scan-user' => $this->scan('user', $argv[2] ?? null, $argv), 'guard:scan-site' => $this->scan('site', $argv[2] ?? null, $argv), 'guard:logs' => $this->logs($argv),
                'guard:backup-detect' => $this->backupDetect(), 'guard:backups:list-users' => $this->backupUsers(), 'guard:backups:list' => $this->backupList($argv), 'guard:backups:find-file' => $this->backupFind($argv), 'guard:backups:preview' => $this->backupPreview($argv), 'guard:backups:diff' => $this->backupDiff($argv), 'guard:backups:restore-file' => $this->backupRestore($argv),
                'guard:scan-unlock' => $this->scanUnlock($argv), 'guard:cleanup-running-scans' => $this->cleanupRunningScans($argv), 'guard:prune' => $this->prune($argv), 'guard:db-stats' => $this->dbStats(), 'guard:optimize-db' => $this->optimizeDb(),
                'guard:quarantine' => $this->quarantine((int)($argv[2] ?? 0)), 'guard:restore' => $this->restore((int)($argv[2] ?? 0)), 'guard:status' => $this->status(), 'key:generate','config:cache','package:discover' => $this->noop($cmd), default => $this->help()
            };
        } catch (\Throwable $e) { fwrite(STDERR, "ERROR: {$e->getMessage()}\n"); return 1; }
    }

    private function help(): int { echo "Jura Server Guard artisan commands:\n  guard:scan [--profile=fast|standard|deep] [--force] [--no-lock] [--include-old] [--include-storage] [--include-backups] [--max-files=N] [--max-seconds=N] [--dry-run]\n  guard:scan-user {user}\n  guard:scan-site {path}\n  guard:logs [--force] [--no-lock]\n  guard:scan-unlock [--force]\n  guard:cleanup-running-scans [--hours=2]\n  guard:prune [--days=30]\n  guard:db-stats\n  guard:optimize-db\n  guard:quarantine {finding_id}\n  guard:restore {quarantine_id}\n  guard:status\n  migrate\n  serve --host=127.0.0.1 --port=8765\n"; return 0; }
    private function noop(string $cmd): int { if ($cmd==='key:generate') $this->ensureKey(); echo "$cmd complete.\n"; return 0; }
    private function ensureKey(): void { $env=base_path('.env'); if (!is_file($env) && is_file(base_path('.env.example'))) copy(base_path('.env.example'), $env); if (is_file($env)) { $c=file_get_contents($env); if (preg_match('/^APP_KEY=\s*$/m',$c)) file_put_contents($env,preg_replace('/^APP_KEY=\s*$/m','APP_KEY=base64:'.base64_encode(random_bytes(32)),$c)); } }

    private function serve(array $argv): int
    {
        $host = env_value('JURA_BIND_HOST', '127.0.0.1'); $port = env_value('JURA_PORT', '8765');
        foreach ($argv as $a) { if (str_starts_with($a, '--host=')) $host = substr($a, 7); if (str_starts_with($a, '--port=')) $port = substr($a, 7); }
        $php = $this->phpBinaryForServer();
        passthru(sprintf('%s -S %s:%s -t %s %s', escapeshellarg($php), escapeshellarg($host), escapeshellarg($port), escapeshellarg(base_path('public')), escapeshellarg(base_path('public/index.php'))), $code);
        return (int)$code;
    }
    private function phpBinaryForServer(): string { $configured = trim((string) env_value('JURA_PHP_BIN', '')); return ($configured !== '' && is_executable($configured)) ? $configured : PHP_BINARY; }

    private function migrate(): int
    {
        $driver = DB::driver();
        $file = base_path('database/migrations/0001_create_guard_tables' . ($driver === 'mysql' ? '.mysql' : '') . '.sql');
        foreach (array_filter(array_map('trim', explode(';', file_get_contents($file)))) as $sql) DB::pdo()->exec($sql);
        $this->ensureSchemaCompatibility();
        (new RuleRepository())->seedDefaults();
        echo "Migrated {$driver} database" . ($driver === 'sqlite' ? ': '.DB::path() : '.') . "\n";
        return 0;
    }

    private function ensureSchemaCompatibility(): void
    {
        $driver = DB::driver();

        $this->ensureColumn('file_snapshots', 'path_hash', $driver === 'mysql' ? 'CHAR(64) NULL' : 'TEXT NULL');
        $this->ensureColumn('findings', 'path_hash', $driver === 'mysql' ? 'CHAR(64) NULL' : 'TEXT NULL');
        $this->ensureColumn('findings', 'finding_hash', $driver === 'mysql' ? 'CHAR(64) NULL' : 'TEXT NULL');
        $this->ensureColumn('findings', 'fingerprint', $driver === 'mysql' ? 'CHAR(64) NULL' : 'TEXT NULL');
        $this->ensureColumn('findings', 'rule_key', $driver === 'mysql' ? 'VARCHAR(128) NULL' : 'TEXT NULL');
        $this->ensureColumn('findings', 'related_log_event_ids', $driver === 'mysql' ? 'LONGTEXT NULL' : 'TEXT NULL');
        $this->ensureColumn('quarantine_items', 'original_path_hash', $driver === 'mysql' ? 'CHAR(64) NULL' : 'TEXT NULL');
        $this->ensureColumn('log_events', 'uri_hash', $driver === 'mysql' ? 'CHAR(64) NULL' : 'TEXT NULL');
        $this->ensureColumn('scan_runs', 'profile', $driver === 'mysql' ? "VARCHAR(32) NOT NULL DEFAULT 'fast'" : "TEXT NOT NULL DEFAULT 'fast'");
        $this->ensureColumn('scan_runs', 'files_scanned', $driver === 'mysql' ? 'BIGINT NOT NULL DEFAULT 0' : 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scan_runs', 'skipped_media', $driver === 'mysql' ? 'BIGINT NOT NULL DEFAULT 0' : 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scan_runs', 'skipped_directories', $driver === 'mysql' ? 'BIGINT NOT NULL DEFAULT 0' : 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scan_runs', 'findings_count', $driver === 'mysql' ? 'BIGINT NOT NULL DEFAULT 0' : 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scan_runs', 'findings_new', $driver === 'mysql' ? 'BIGINT NOT NULL DEFAULT 0' : 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scan_runs', 'scope_type', $driver === 'mysql' ? "VARCHAR(32) NOT NULL DEFAULT 'full'" : "TEXT NOT NULL DEFAULT 'full'");
        $this->ensureColumn('scan_runs', 'scope_value', $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');
        $this->ensureColumn('scan_runs', 'error_text', $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');
        $this->backfillScanRunCompatibilityColumns();
        $this->ensureRestoreActionsTable($driver);

        foreach (DB::select('SELECT id,path FROM file_snapshots WHERE path_hash IS NULL OR path_hash = ?', ['']) as $row) DB::statement('UPDATE file_snapshots SET path_hash=? WHERE id=?', [hash('sha256', (string)$row['path']), $row['id']]);
        foreach (DB::select('SELECT id,path,type,rule_key,fingerprint,sha256 FROM findings WHERE path_hash IS NULL OR path_hash = ? OR finding_hash IS NULL OR finding_hash = ?', ['', '']) as $row) {
            $path = (string)$row['path'];
            $type = (string)($row['type'] ?? 'unknown');
            $rule = (string)($row['rule_key'] ?? '');
            $fingerprint = (string)($row['fingerprint'] ?? '');
            if ($fingerprint === '') $fingerprint = hash('sha256', $path.'|'.$type.'|'.$rule.'|'.($row['sha256'] ?? ''));
            DB::statement('UPDATE findings SET path_hash=?, fingerprint=?, finding_hash=? WHERE id=?', [hash('sha256', $path), $fingerprint, hash('sha256', $path.'|'.$type.'|'.$rule.'|'.$fingerprint), $row['id']]);
        }
        foreach (DB::select('SELECT id,original_path FROM quarantine_items WHERE original_path_hash IS NULL OR original_path_hash = ?', ['']) as $row) DB::statement('UPDATE quarantine_items SET original_path_hash=? WHERE id=?', [hash('sha256', (string)$row['original_path']), $row['id']]);
        foreach (DB::select('SELECT id,uri FROM log_events WHERE uri IS NOT NULL AND (uri_hash IS NULL OR uri_hash = ?)', ['']) as $row) DB::statement('UPDATE log_events SET uri_hash=? WHERE id=?', [hash('sha256', (string)$row['uri']), $row['id']]);

        if ($driver === 'mysql') {
            foreach (['file_snapshots_path_unique', 'findings_path_idx', 'findings_fingerprint_idx', 'log_events_uri_idx', 'quarantine_items_original_path_idx'] as $index) {
                try { DB::pdo()->exec("DROP INDEX $index ON " . $this->indexTable($index)); } catch (\Throwable) {}
            }
            try { DB::pdo()->exec('ALTER TABLE file_snapshots MODIFY path_hash CHAR(64) NOT NULL'); } catch (\Throwable) {}
            try { DB::pdo()->exec('ALTER TABLE findings MODIFY path_hash CHAR(64) NOT NULL, MODIFY finding_hash CHAR(64) NOT NULL'); } catch (\Throwable) {}
        } else {
            foreach (['file_snapshots_path_unique', 'findings_path_idx', 'findings_fingerprint_idx', 'log_events_uri_idx', 'quarantine_items_original_path_idx'] as $index) {
                try { DB::pdo()->exec('DROP INDEX IF EXISTS ' . $index); } catch (\Throwable) {}
            }
        }

        $indexes = $driver === 'mysql' ? [
            'CREATE UNIQUE INDEX uniq_file_snapshots_path_hash ON file_snapshots(path_hash)', 'CREATE INDEX idx_file_snapshots_path_prefix ON file_snapshots(path(191))', 'CREATE INDEX file_snapshots_site_id_idx ON file_snapshots(site_id)', 'CREATE INDEX file_snapshots_sha256_idx ON file_snapshots(sha256)', 'CREATE INDEX idx_findings_path_hash ON findings(path_hash)', 'CREATE INDEX idx_findings_path_prefix ON findings(path(191))', 'CREATE INDEX findings_status_idx ON findings(status)', 'CREATE INDEX findings_risk_idx ON findings(risk)', 'CREATE INDEX findings_site_id_idx ON findings(site_id)', 'CREATE INDEX findings_finding_hash_idx ON findings(finding_hash,status)', 'CREATE INDEX findings_scan_run_id_idx ON findings(scan_run_id)', 'CREATE INDEX scan_runs_status_idx ON scan_runs(status)', 'CREATE INDEX log_events_site_id_idx ON log_events(site_id)', 'CREATE INDEX log_events_uri_hash_idx ON log_events(uri_hash)', 'CREATE INDEX log_events_uri_prefix_idx ON log_events(uri(191))', 'CREATE INDEX log_events_ip_idx ON log_events(ip)', 'CREATE INDEX idx_quarantine_original_path_hash ON quarantine_items(original_path_hash)', 'CREATE INDEX quarantine_items_original_path_prefix_idx ON quarantine_items(original_path(191))', 'CREATE INDEX quarantine_items_finding_id_idx ON quarantine_items(finding_id)'
        ] : [
            'CREATE UNIQUE INDEX IF NOT EXISTS uniq_file_snapshots_path_hash ON file_snapshots(path_hash)', 'CREATE INDEX IF NOT EXISTS idx_file_snapshots_path_prefix ON file_snapshots(substr(path,1,191))', 'CREATE INDEX IF NOT EXISTS file_snapshots_site_id_idx ON file_snapshots(site_id)', 'CREATE INDEX IF NOT EXISTS file_snapshots_sha256_idx ON file_snapshots(sha256)', 'CREATE INDEX IF NOT EXISTS idx_findings_path_hash ON findings(path_hash)', 'CREATE INDEX IF NOT EXISTS idx_findings_path_prefix ON findings(substr(path,1,191))', 'CREATE INDEX IF NOT EXISTS findings_status_idx ON findings(status)', 'CREATE INDEX IF NOT EXISTS findings_risk_idx ON findings(risk)', 'CREATE INDEX IF NOT EXISTS findings_site_id_idx ON findings(site_id)', 'CREATE INDEX IF NOT EXISTS findings_finding_hash_idx ON findings(finding_hash,status)', 'CREATE INDEX IF NOT EXISTS scan_runs_status_idx ON scan_runs(status)', 'CREATE INDEX IF NOT EXISTS log_events_site_id_idx ON log_events(site_id)', 'CREATE INDEX IF NOT EXISTS log_events_uri_hash_idx ON log_events(uri_hash)', 'CREATE INDEX IF NOT EXISTS log_events_uri_prefix_idx ON log_events(substr(uri,1,191))', 'CREATE INDEX IF NOT EXISTS log_events_ip_idx ON log_events(ip)', 'CREATE INDEX IF NOT EXISTS idx_quarantine_original_path_hash ON quarantine_items(original_path_hash)', 'CREATE INDEX IF NOT EXISTS quarantine_items_original_path_prefix_idx ON quarantine_items(substr(original_path,1,191))'
        ];
        foreach ($indexes as $sql) { try { DB::pdo()->exec($sql); } catch (\Throwable) {} }
    }



    private function backfillScanRunCompatibilityColumns(): void
    {
        $columns = $this->columns('scan_runs');
        if (in_array('findings_new', $columns, true) && in_array('findings_count', $columns, true)) {
            DB::statement('UPDATE scan_runs SET findings_new = findings_count WHERE COALESCE(findings_new, 0) = 0 AND COALESCE(findings_count, 0) <> 0');
            DB::statement('UPDATE scan_runs SET findings_count = findings_new WHERE COALESCE(findings_count, 0) = 0 AND COALESCE(findings_new, 0) <> 0');
        }
    }

    private function ensureRestoreActionsTable(string $driver): void
    {
        if ($driver === 'mysql') DB::pdo()->exec("CREATE TABLE IF NOT EXISTS restore_actions (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, admin_user_id BIGINT UNSIGNED NULL, original_path VARCHAR(2048) NOT NULL, backup_provider VARCHAR(64) NOT NULL, backup_user VARCHAR(255) NULL, backup_date VARCHAR(64) NULL, backup_source_archive TEXT NULL, previous_sha256 CHAR(64) NULL, restored_sha256 CHAR(64) NULL, previous_size BIGINT NULL, restored_size BIGINT NULL, quarantine_path TEXT NULL, created_at DATETIME NULL, status VARCHAR(32) NOT NULL DEFAULT 'pending', error_message TEXT NULL, INDEX restore_actions_path_idx(original_path(191))) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        else DB::pdo()->exec("CREATE TABLE IF NOT EXISTS restore_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_user_id INTEGER NULL, original_path TEXT NOT NULL, backup_provider TEXT NOT NULL, backup_user TEXT NULL, backup_date TEXT NULL, backup_source_archive TEXT NULL, previous_sha256 TEXT NULL, restored_sha256 TEXT NULL, previous_size INTEGER NULL, restored_size INTEGER NULL, quarantine_path TEXT NULL, created_at TEXT, status TEXT NOT NULL DEFAULT 'pending', error_message TEXT NULL)");
    }

    private function ensureColumn(string $table, string $column, string $definition): void
    {
        if (in_array($column, $this->columns($table), true)) return;
        DB::pdo()->exec('ALTER TABLE ' . $table . ' ADD COLUMN ' . $column . ' ' . $definition);
    }

    private function columns(string $table): array
    {
        return DB::driver() === 'mysql'
            ? array_column(DB::select('SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?', [$table]), 'COLUMN_NAME')
            : array_column(DB::select('PRAGMA table_info(' . $table . ')'), 'name');
    }

    private function indexTable(string $index): string
    {
        return match (true) {
            str_starts_with($index, 'file_snapshots') => 'file_snapshots',
            str_starts_with($index, 'findings') => 'findings',
            str_starts_with($index, 'log_events') => 'log_events',
            str_starts_with($index, 'quarantine_items') => 'quarantine_items',
            default => 'sites',
        };
    }

    private function seedRules(): int { (new RuleRepository())->seedDefaults(); echo "Default rules and allowlist seeded.\n"; return 0; }
    private function createAdmin(string $email, string $password): int { $hash=password_hash($password,PASSWORD_DEFAULT); if(DB::first('SELECT id FROM admin_users WHERE email=?',[$email])) DB::statement('UPDATE admin_users SET password_hash=?,updated_at=? WHERE email=?',[$hash,now(),$email]); else DB::insert('INSERT INTO admin_users (email,password_hash,created_at,updated_at) VALUES (?,?,?,?)',[$email,$hash,now(),now()]); echo "Admin login: $email\nAdmin password: $password\n"; return 0; }

    private function scan(string $scope, ?string $value, array $argv): int
    {
        if ($scope !== 'full' && !$value) throw new \InvalidArgumentException('Scope value is required.');
        $options = $this->scanOptions($argv); $lock = new ScanLock();
        if (!$options['no_lock']) $lock->acquire(implode(' ', array_slice($argv, 1)), $options['force']);
        try { $id=(new ScannerService())->scan($scope,$value,$options); echo "Scan run #$id completed.\n"; return 0; }
        finally { if (!$options['no_lock']) $lock->release(); }
    }
    private function logs(array $argv): int { $o=$this->scanOptions($argv); $lock=new ScanLock(); if(!$o['no_lock']) $lock->acquire('guard:logs',$o['force']); try { $n=(new LogAnalyzerService())->analyze(); echo "Stored suspicious log events: $n\n"; return 0; } finally { if(!$o['no_lock']) $lock->release(); } }
    private function scanOptions(array $argv): array { return ['profile'=>$this->optionString($argv,'--profile') ?? (string)config('guard.scan_profile','fast'), 'force'=>in_array('--force',$argv,true), 'no_lock'=>in_array('--no-lock',$argv,true), 'include_old'=>in_array('--include-old',$argv,true), 'include_storage'=>in_array('--include-storage',$argv,true), 'include_backups'=>in_array('--include-backups',$argv,true), 'dry_run'=>in_array('--dry-run',$argv,true), 'verbose'=>in_array('--verbose',$argv,true), 'max_files'=>$this->optionInt($argv,'--max-files'), 'max_seconds'=>$this->optionInt($argv,'--max-seconds')]; }
    private function optionInt(array $argv, string $name): ?int { foreach($argv as $a) if(str_starts_with($a,$name.'=')) return (int)substr($a,strlen($name)+1); return null; }
    private function optionString(array $argv, string $name): ?string { foreach($argv as $a) if(str_starts_with($a,$name.'=')) return substr($a,strlen($name)+1); return null; }
    private function scanUnlock(array $argv): int { echo (new ScanLock())->unlock(in_array('--force',$argv,true))."\n"; return 0; }
    private function cleanupRunningScans(array $argv): int { $h=$this->optionInt($argv,'--hours') ?? 2; DB::statement("UPDATE scan_runs SET status='failed', finished_at=?, error_text=?, updated_at=? WHERE status='running' AND started_at < ".DB::nowMinusHoursSql($h), [now(), "Marked failed by cleanup after {$h} hours", now()]); echo "Old running scan_runs marked failed.\n"; return 0; }
    private function prune(array $argv): int { $d=$this->optionInt($argv,'--days') ?? 30; $cut=gmdate('Y-m-d H:i:s', time()-$d*86400); foreach(['log_events','scan_runs'] as $t) DB::statement("DELETE FROM $t WHERE created_at < ?",[$cut]); DB::statement("DELETE FROM file_snapshots WHERE is_missing=1 AND updated_at < ?",[$cut]); echo "Pruned data older than $d days.\n"; return 0; }
    private function dbStats(): int { echo "DB driver: ".DB::driver()."\n"; foreach(['users','sites','file_snapshots','findings','log_events','scan_runs'] as $t) echo "$t: ".(DB::first("SELECT COUNT(*) c FROM $t")['c']??0)."\n"; if(DB::driver()==='sqlite') echo "DB size: ".(is_file(DB::path()) ? filesize(DB::path()) : 0)." bytes\n"; else foreach(DB::select('SELECT table_name, table_rows, ROUND((data_length+index_length)/1024/1024,2) mb FROM information_schema.tables WHERE table_schema=DATABASE() ORDER BY (data_length+index_length) DESC LIMIT 10') as $r) echo "{$r['table_name']}: {$r['table_rows']} rows, {$r['mb']} MB\n"; return 0; }
    private function optimizeDb(): int { if(DB::driver()==='sqlite') { DB::pdo()->exec('VACUUM'); DB::pdo()->exec('ANALYZE'); } else foreach(['admin_users','users','sites','scan_runs','file_snapshots','findings','log_events','quarantine_items','rules','allowlist_rules','settings','ai_analyses'] as $t) DB::pdo()->exec("OPTIMIZE TABLE $t"); echo "Database optimized.\n"; return 0; }
    private function quarantine(int $id): int { if(!$id) throw new \InvalidArgumentException('finding_id is required.'); $qid=(new QuarantineService())->quarantine($id); echo "Quarantined as item #$qid\n"; return 0; }
    private function restore(int $id): int { if(!$id) throw new \InvalidArgumentException('quarantine_id is required.'); (new QuarantineService())->restore($id); echo "Restored quarantine item #$id\n"; return 0; }

    private function backupDetect(): int { $d=(new IspmanagerBackupService())->detectTools(); echo "Backup root exists: ".($d['root_exists']?'yes':'no')."\nISPmanager /usr/local/mgr5: ".($d['mgr5_exists']?'yes':'no')."\nTools:\n".implode("\n", $d['tools'])."\n"; return 0; }
    private function backupUsers(): int { foreach((new IspmanagerBackupService())->users() as $u) echo $u."\n"; return 0; }
    private function backupList(array $argv): int { foreach((new IspmanagerBackupService())->backups($this->optionString($argv,'--user')) as $b) echo "{$b['user']}\t{$b['date']}\t{$b['type']}\t{$b['path']}\n"; return 0; }
    private function backupFind(array $argv): int { $path=$this->optionString($argv,'--path') ?? throw new \InvalidArgumentException('--path required'); foreach((new IspmanagerBackupService())->findFile($path) as $f) echo "{$f['date']}\t{$f['backup_type']}\t{$f['source']}\t{$f['size']}\n"; return 0; }
    private function backupPreview(array $argv): int { echo (new IspmanagerBackupService())->preview($this->optionString($argv,'--path') ?? throw new \InvalidArgumentException('--path required'), $this->optionString($argv,'--date') ?? throw new \InvalidArgumentException('--date required')); return 0; }
    private function backupDiff(array $argv): int { echo (new IspmanagerBackupService())->diff($this->optionString($argv,'--path') ?? throw new \InvalidArgumentException('--path required'), $this->optionString($argv,'--date') ?? throw new \InvalidArgumentException('--date required'))."\n"; return 0; }
    private function backupRestore(array $argv): int { $id=(new IspmanagerBackupService())->restore($this->optionString($argv,'--path') ?? throw new \InvalidArgumentException('--path required'), $this->optionString($argv,'--date') ?? throw new \InvalidArgumentException('--date required')); echo "Restore action #$id completed.\n"; return 0; }

    private function status(): int { $last=DB::first('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1')?:[]; $users=DB::first('SELECT COUNT(*) c FROM users')['c']??0; $sites=DB::first('SELECT COUNT(*) c FROM sites')['c']??0; $find=DB::first("SELECT COUNT(*) c FROM findings WHERE status='new'")['c']??0; echo "Jura Server Guard status\nDB: ".DB::driver()."\nUsers: $users\nSites: $sites\nNew findings: $find\nLast scan: ".($last['started_at']??'never')." (".($last['status']??'n/a').")\n"; return 0; }
}
