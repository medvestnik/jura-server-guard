<?php
namespace App\Console;

use App\Modules\Backups\IspmanagerBackupService;
use App\Modules\Incidents\IncidentImportService;
use App\Modules\LogAnalyzer\LogAnalyzerService;
use App\Modules\Notifications\AlertService;
use App\Modules\Notifications\TelegramNotifier;
use App\Modules\Quarantine\QuarantineService;
use App\Modules\Quarantine\BulkFindingActionService;
use App\Modules\Rules\RuleRepository;
use App\Modules\Scanner\ScannerService;
use App\Support\DB;
use App\Support\ScanLock;

class Application
{
    public function run(array $argv): int
    {
        $cmd = $argv[1] ?? 'list';
        if (in_array('--help', $argv, true) || in_array('-h', $argv, true)) return $this->help($cmd);
        try {
            return match ($cmd) {
                'serve' => $this->serve($argv), 'migrate' => $this->migrate(), 'guard:seed-rules' => $this->seedRules(), 'guard:create-admin' => $this->createAdmin($argv[2] ?? env_value('JURA_ADMIN_EMAIL','admin@example.com'), $argv[3] ?? bin2hex(random_bytes(12))),
                'guard:scan' => $this->scan('full', null, $argv), 'guard:scan-user' => $this->scan('user', $argv[2] ?? null, $argv), 'guard:scan-site' => $this->scan('site', $argv[2] ?? null, $argv), 'guard:logs' => $this->logs($argv),
                'guard:backup-detect' => $this->backupDetect(), 'guard:backups:list-users' => $this->backupUsers(), 'guard:backups:list' => $this->backupList($argv), 'guard:backups:find-file' => $this->backupFind($argv), 'guard:backups:preview' => $this->backupPreview($argv), 'guard:backups:diff' => $this->backupDiff($argv), 'guard:backups:restore-file' => $this->backupRestore($argv),
                'guard:signature-list' => $this->signatureList(), 'guard:signature-test' => $this->signatureTest((int)($argv[2] ?? 0), $argv[3] ?? ''), 'guard:signature-sweep' => $this->signatureSweep((int)($argv[2] ?? 0)), 'guard:signature-suggest' => $this->signatureSuggest((int)($argv[2] ?? 0)), 'guard:signature-enable' => $this->signatureToggle((int)($argv[2] ?? 0), true), 'guard:signature-disable' => $this->signatureToggle((int)($argv[2] ?? 0), false), 'guard:scan-active' => $this->scanActive(), 'guard:scan-unlock' => $this->scanUnlock($argv), 'guard:cleanup-running-scans' => $this->cleanupRunningScans($argv), 'guard:prune' => $this->prune($argv), 'guard:db-stats' => $this->dbStats(), 'guard:optimize-db' => $this->optimizeDb(),
                'guard:sites' => $this->sites(), 'guard:quarantine' => $this->quarantine((int)($argv[2] ?? 0)), 'guard:restore' => $this->restore((int)($argv[2] ?? 0)), 'guard:findings-bulk-action' => $this->bulkFindingsAction((string)($argv[2] ?? '')), 'guard:status' => $this->status(),
                'guard:ip-list' => $this->ipList(), 'guard:ip-add' => $this->ipAdd($argv), 'guard:ip-remove' => $this->ipRemove($argv), 'guard:find-hash' => $this->findHash($argv),
                'guard:incident-import' => $this->incidentImport($argv), 'guard:incident-list' => $this->incidentList(),
                'guard:trust-ip' => $this->trustIp($argv), 'guard:untrust-ip' => $this->untrustIp($argv), 'guard:trusted-ips' => $this->trustedIpsList(),
                'guard:cron-scan' => $this->cronScan(), 'guard:telegram-test' => $this->telegramTest($argv), 'guard:telegram-findings' => $this->telegramFindings($argv),
                'key:generate','config:cache','package:discover' => $this->noop($cmd), default => $this->help()
            };
        } catch (\Throwable $e) { fwrite(STDERR, "ERROR: {$e->getMessage()}\n"); return 1; }
    }

    private function help(?string $cmd = null): int { echo "Jura Server Guard artisan commands:\n  guard:scan [--profile=fast|standard|deep] [--diff|--changed-only|--full-rescan|--paranoid] [--force] [--no-lock] [--include-old] [--include-storage] [--include-backups] [--include-vendor] [--max-files=N] [--max-seconds=N] [--dry-run] [--include-logs] [--skip-logs]\n  guard:scan-user {user} [--profile=fast|standard|deep] [--diff|--changed-only|--full-rescan|--paranoid] [--force] [--no-lock] [--max-files=N] [--max-seconds=N] [--dry-run] [--include-logs] [--skip-logs]\n  guard:scan-site {path} [--profile=fast|standard|deep] [--diff|--changed-only|--full-rescan|--paranoid] [--force] [--no-lock] [--max-files=N] [--max-seconds=N] [--dry-run] [--include-logs] [--skip-logs]\n    Log defaults: fast and changed-only skip logs; standard includes limited log analysis; deep includes log analysis. Use --include-logs to force logs or --skip-logs to suppress them.\n  guard:signature-list\n  guard:signature-test {signature_id} {file_path}\n  guard:signature-sweep {signature_id}\n  guard:signature-suggest {finding_id}\n  guard:signature-enable {signature_id}\n  guard:signature-disable {signature_id}\n  guard:sites\n  guard:logs [--force] [--no-lock]\n  guard:scan-active\n  guard:scan-unlock [--force]\n  guard:cleanup-running-scans [--hours=2]\n  guard:prune [--days=30]\n  guard:db-stats\n  guard:optimize-db\n  guard:quarantine {finding_id}\n  guard:restore {quarantine_id}\n  guard:status\n  guard:ip-list\n  guard:ip-add {ip} [--classification=scanner|bruteforce|webshell_access|bot|direct_login|manual|unknown] [--risk=low|medium|high|critical] [--notes=TEXT]\n  guard:ip-remove {ip}\n  guard:find-hash {sha256}\n  guard:incident-import {path.json} [--dry-run]\n  guard:incident-list\n  guard:trust-ip {ip} [--label=TEXT] [--notes=TEXT]\n  guard:untrust-ip {ip}\n  guard:trusted-ips\n  guard:cron-scan\n  guard:telegram-test [--message=TEXT]\n  guard:telegram-findings [scan_run_id]\n  migrate\n  serve --host=127.0.0.1 --port=8765\n"; return 0; }
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
        foreach (array_filter(array_map('trim', explode(';', file_get_contents($file)))) as $sql) {
            try { DB::pdo()->exec($sql); } catch (\Throwable $e) { fwrite(STDERR, "WARNING: base migration statement failed, continuing: {$e->getMessage()}\n"); }
        }
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
        if ($driver === 'mysql') {
            try { DB::pdo()->exec('ALTER TABLE log_events MODIFY uri LONGTEXT NULL, MODIFY raw_line LONGTEXT NOT NULL'); } catch (\Throwable) {}
        }
        foreach (['cms_version','cms_admin_path','cms_notes'] as $col) $this->ensureColumn('sites', $col, $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');
        $this->ensureColumn('sites', 'cms_detected_at', $driver === 'mysql' ? 'DATETIME NULL' : 'TEXT NULL');
        if ($driver === 'mysql') { try { DB::pdo()->exec('ALTER TABLE sites MODIFY cms_detected_at DATETIME NULL'); } catch (\Throwable) {} }
        $this->ensureColumn('sites', 'cms_confidence', $driver === 'mysql' ? 'INT NULL' : 'INTEGER NULL');
        foreach (['first_seen_scan_id','last_seen_scan_id','last_matched_signature_id'] as $col) $this->ensureColumn('findings', $col, $driver === 'mysql' ? 'BIGINT NULL' : 'INTEGER NULL');
        foreach (['matched_signature_name','matched_signature_source','signature_match_details'] as $col) $this->ensureColumn('findings', $col, $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');
        $this->ensureColumn('findings', 'telegram_notified_at', $driver === 'mysql' ? 'DATETIME NULL' : 'TEXT NULL');
        $this->ensureColumn('findings', 'telegram_notification_error', $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');
        $this->ensureColumn('file_snapshots', 'telegram_notified_at', $driver === 'mysql' ? 'DATETIME NULL' : 'TEXT NULL');
        $this->ensureColumn('file_snapshots', 'telegram_notification_error', $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');
        $this->ensureSignatureTables($driver);
        $this->seedBuiltinSignatures();
        $emptyHash = hash('sha256', '');
        DB::statement("UPDATE malware_signatures SET enabled=0,updated_at=? WHERE source='auto_finding' AND (source_file_sha256=? OR pattern_json LIKE ?)", [now(),$emptyHash,'%'.$emptyHash.'%']);
        DB::statement("UPDATE findings SET status='ignored',updated_at=? WHERE status='new' AND size=0 AND sha256=? AND matched_signature_source='auto_finding'", [now(),$emptyHash]);

        $this->ensureColumn('scan_runs', 'profile', $driver === 'mysql' ? "VARCHAR(32) NOT NULL DEFAULT 'fast'" : "TEXT NOT NULL DEFAULT 'fast'");
        $this->ensureColumn('scan_runs', 'files_scanned', $driver === 'mysql' ? 'BIGINT NOT NULL DEFAULT 0' : 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scan_runs', 'skipped_media', $driver === 'mysql' ? 'BIGINT NOT NULL DEFAULT 0' : 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scan_runs', 'skipped_directories', $driver === 'mysql' ? 'BIGINT NOT NULL DEFAULT 0' : 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scan_runs', 'findings_count', $driver === 'mysql' ? 'BIGINT NOT NULL DEFAULT 0' : 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scan_runs', 'findings_new', $driver === 'mysql' ? 'BIGINT NOT NULL DEFAULT 0' : 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scan_runs', 'scope_type', $driver === 'mysql' ? "VARCHAR(32) NOT NULL DEFAULT 'full'" : "TEXT NOT NULL DEFAULT 'full'");
        $this->ensureColumn('scan_runs', 'scope_value', $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');
        $this->ensureColumn('scan_runs', 'error_text', $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');

        $this->ensureColumn('scan_runs', 'pid', $driver === 'mysql' ? 'BIGINT NULL' : 'INTEGER NULL');
        $this->ensureColumn('scan_runs', 'current_site', $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');
        $this->ensureColumn('scan_runs', 'current_path', $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');
        $this->ensureColumn('scan_runs', 'total_files_estimated', $driver === 'mysql' ? 'BIGINT NULL' : 'INTEGER NULL');
        $this->ensureColumn('scan_runs', 'last_heartbeat_at', $driver === 'mysql' ? 'DATETIME NULL' : 'TEXT NULL');
        $this->ensureColumn('scan_runs', 'progress_message', $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');

        $this->ensureColumn('scan_runs', 'scan_mode', $driver === 'mysql' ? "VARCHAR(32) NOT NULL DEFAULT 'differential'" : "TEXT NOT NULL DEFAULT 'differential'");
        $this->ensureColumn('scan_runs', 'previous_scan_id', $driver === 'mysql' ? 'BIGINT NULL' : 'INTEGER NULL');
        foreach (['files_seen_total','files_new','files_modified','files_deleted','files_changed_total','files_analyzed','files_skipped_unchanged'] as $col) $this->ensureColumn('scan_runs', $col, $driver === 'mysql' ? 'BIGINT NOT NULL DEFAULT 0' : 'INTEGER NOT NULL DEFAULT 0');
        foreach (['site_manifest_hash','file_list_hash','directory_list_hash','metadata_hash'] as $col) $this->ensureColumn('scan_runs', $col, $driver === 'mysql' ? 'CHAR(64) NULL' : 'TEXT NULL');
        $this->ensureColumn('scan_runs', 'diff_summary', $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');
        foreach (['ctime','inode','mode','uid','gid','extension','file_category','content_hash','first_seen_scan_id','last_seen_scan_id','last_changed_scan_id','baseline_status','trusted_baseline_at'] as $col) {
            $def = in_array($col, ['first_seen_scan_id','last_seen_scan_id','last_changed_scan_id'], true) ? ($driver === 'mysql' ? 'BIGINT NULL' : 'INTEGER NULL') : ($driver === 'mysql' ? 'VARCHAR(255) NULL' : 'TEXT NULL');
            if ($col === 'content_hash') $def = $driver === 'mysql' ? 'CHAR(64) NULL' : 'TEXT NULL';
            if ($col === 'trusted_baseline_at') $def = $driver === 'mysql' ? 'DATETIME NULL' : 'TEXT NULL';
            $this->ensureColumn('file_snapshots', $col, $def);
        }
        $this->backfillScanRunCompatibilityColumns();
        $this->ensureRestoreActionsTable($driver);
        $this->ensureThreatIpsTable($driver);
        $this->ensureThreatIpEvidenceTable($driver);
        $this->ensureIncidentTables($driver);
        $this->ensureAiChatTable($driver);

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
            'CREATE UNIQUE INDEX uniq_file_snapshots_path_hash ON file_snapshots(path_hash)', 'CREATE INDEX idx_file_snapshots_path_prefix ON file_snapshots(path(191))', 'CREATE INDEX file_snapshots_site_id_idx ON file_snapshots(site_id)', 'CREATE INDEX file_snapshots_site_path_hash_idx ON file_snapshots(site_id,path_hash)', 'CREATE INDEX file_snapshots_site_last_seen_idx ON file_snapshots(site_id,last_seen_scan_id)', 'CREATE INDEX file_snapshots_sha256_idx ON file_snapshots(sha256)', 'CREATE INDEX idx_findings_path_hash ON findings(path_hash)', 'CREATE INDEX idx_findings_path_prefix ON findings(path(191))', 'CREATE INDEX findings_status_idx ON findings(status)', 'CREATE INDEX findings_risk_idx ON findings(risk)', 'CREATE INDEX findings_site_id_idx ON findings(site_id)', 'CREATE INDEX findings_finding_hash_idx ON findings(finding_hash,status)', 'CREATE INDEX findings_scan_run_id_idx ON findings(scan_run_id)', 'CREATE INDEX scan_runs_status_idx ON scan_runs(status)', 'CREATE INDEX scan_runs_site_status_finished_idx ON scan_runs(scope_type,scope_value(191),status,finished_at)', 'CREATE INDEX log_events_site_id_idx ON log_events(site_id)', 'CREATE INDEX log_events_uri_hash_idx ON log_events(uri_hash)',  'CREATE INDEX log_events_ip_idx ON log_events(ip)', 'CREATE INDEX idx_quarantine_original_path_hash ON quarantine_items(original_path_hash)', 'CREATE INDEX quarantine_items_original_path_prefix_idx ON quarantine_items(original_path(191))', 'CREATE INDEX quarantine_items_finding_id_idx ON quarantine_items(finding_id)'
        ] : [
            'CREATE UNIQUE INDEX IF NOT EXISTS uniq_file_snapshots_path_hash ON file_snapshots(path_hash)', 'CREATE INDEX IF NOT EXISTS idx_file_snapshots_path_prefix ON file_snapshots(substr(path,1,191))', 'CREATE INDEX IF NOT EXISTS file_snapshots_site_id_idx ON file_snapshots(site_id)', 'CREATE INDEX IF NOT EXISTS file_snapshots_site_path_hash_idx ON file_snapshots(site_id,path_hash)', 'CREATE INDEX IF NOT EXISTS file_snapshots_site_last_seen_idx ON file_snapshots(site_id,last_seen_scan_id)', 'CREATE INDEX IF NOT EXISTS file_snapshots_sha256_idx ON file_snapshots(sha256)', 'CREATE INDEX IF NOT EXISTS idx_findings_path_hash ON findings(path_hash)', 'CREATE INDEX IF NOT EXISTS idx_findings_path_prefix ON findings(substr(path,1,191))', 'CREATE INDEX IF NOT EXISTS findings_status_idx ON findings(status)', 'CREATE INDEX IF NOT EXISTS findings_risk_idx ON findings(risk)', 'CREATE INDEX IF NOT EXISTS findings_site_id_idx ON findings(site_id)', 'CREATE INDEX IF NOT EXISTS findings_finding_hash_idx ON findings(finding_hash,status)', 'CREATE INDEX IF NOT EXISTS scan_runs_status_idx ON scan_runs(status)', 'CREATE INDEX IF NOT EXISTS scan_runs_site_status_finished_idx ON scan_runs(scope_type,scope_value,status,finished_at)', 'CREATE INDEX IF NOT EXISTS log_events_site_id_idx ON log_events(site_id)', 'CREATE INDEX IF NOT EXISTS log_events_uri_hash_idx ON log_events(uri_hash)', 'CREATE INDEX IF NOT EXISTS log_events_uri_prefix_idx ON log_events(substr(uri,1,191))', 'CREATE INDEX IF NOT EXISTS log_events_ip_idx ON log_events(ip)', 'CREATE INDEX IF NOT EXISTS idx_quarantine_original_path_hash ON quarantine_items(original_path_hash)', 'CREATE INDEX IF NOT EXISTS quarantine_items_original_path_prefix_idx ON quarantine_items(substr(original_path,1,191))'
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


    private function ensureSignatureTables(string $driver): void
    {
        if ($driver === 'mysql') {
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS malware_signatures (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255) NOT NULL, slug VARCHAR(255) NOT NULL UNIQUE, description TEXT NULL, risk VARCHAR(32) NOT NULL, type VARCHAR(64) NOT NULL, pattern_type VARCHAR(32) NOT NULL, pattern_json LONGTEXT NOT NULL, target_extensions LONGTEXT NULL, target_paths LONGTEXT NULL, exclude_paths LONGTEXT NULL, required_hits INT NULL, enabled TINYINT(1) NOT NULL DEFAULT 1, source VARCHAR(32) NOT NULL DEFAULT 'manual', source_finding_id BIGINT NULL, source_file_sha256 CHAR(64) NULL, confidence DECIMAL(5,2) NULL, false_positive_notes TEXT NULL, created_at DATETIME NULL, updated_at DATETIME NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS signature_suggestions (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, finding_id BIGINT NULL, source_file_path TEXT NULL, source_file_sha256 CHAR(64) NULL, ai_provider VARCHAR(64) NULL, model VARCHAR(128) NULL, status VARCHAR(32) NOT NULL DEFAULT 'draft', suggested_name VARCHAR(255) NULL, suggested_risk VARCHAR(32) NULL, suggested_type VARCHAR(64) NULL, suggested_pattern_type VARCHAR(32) NULL, suggested_pattern_json LONGTEXT NULL, explanation TEXT NULL, test_result_json LONGTEXT NULL, created_at DATETIME NULL, updated_at DATETIME NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS site_path_whitelist (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, site_id BIGINT NULL, path TEXT NOT NULL, path_type VARCHAR(32) NOT NULL DEFAULT 'file', reason TEXT NULL, approved_by BIGINT NULL, approved_at DATETIME NULL, expires_at DATETIME NULL, created_at DATETIME NULL, updated_at DATETIME NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        } else {
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS malware_signatures (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, description TEXT NULL, risk TEXT NOT NULL, type TEXT NOT NULL, pattern_type TEXT NOT NULL, pattern_json TEXT NOT NULL, target_extensions TEXT NULL, target_paths TEXT NULL, exclude_paths TEXT NULL, required_hits INTEGER NULL, enabled INTEGER NOT NULL DEFAULT 1, source TEXT NOT NULL DEFAULT 'manual', source_finding_id INTEGER NULL, source_file_sha256 TEXT NULL, confidence REAL NULL, false_positive_notes TEXT NULL, created_at TEXT, updated_at TEXT)");
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS signature_suggestions (id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NULL, source_file_path TEXT NULL, source_file_sha256 TEXT NULL, ai_provider TEXT NULL, model TEXT NULL, status TEXT NOT NULL DEFAULT 'draft', suggested_name TEXT NULL, suggested_risk TEXT NULL, suggested_type TEXT NULL, suggested_pattern_type TEXT NULL, suggested_pattern_json TEXT NULL, explanation TEXT NULL, test_result_json TEXT NULL, created_at TEXT, updated_at TEXT)");
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS site_path_whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER NULL, path TEXT NOT NULL, path_type TEXT NOT NULL DEFAULT 'file', reason TEXT NULL, approved_by INTEGER NULL, approved_at TEXT NULL, expires_at TEXT NULL, created_at TEXT, updated_at TEXT)");
        }
    }


    private function seedBuiltinSignatures(): void
    {
        foreach ((new \App\Modules\Scanner\SignatureEngine())->builtinSignatures() as $sig) {
            if (DB::first('SELECT id FROM malware_signatures WHERE slug=?', [$sig['slug']])) continue;
            DB::insert('INSERT INTO malware_signatures (name,slug,description,risk,type,pattern_type,pattern_json,target_extensions,enabled,source,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,1,?,?,?)', [$sig['name'],$sig['slug'],$sig['description'],$sig['risk'],$sig['type'],$sig['pattern_type'],$sig['pattern_json'],$sig['target_extensions'],'builtin',now(),now()]);
        }
    }

    private function signatureList(): int
    {
        foreach (DB::select('SELECT id,name,risk,type,pattern_type,source,enabled FROM malware_signatures ORDER BY id') as $r) echo implode("\t", $r) . "\n";
        return 0;
    }

    private function signatureToggle(int $id, bool $enabled): int
    {
        DB::statement('UPDATE malware_signatures SET enabled=?,updated_at=? WHERE id=?', [$enabled ? 1 : 0, now(), $id]);
        echo ($enabled ? 'Enabled' : 'Disabled') . " signature #$id\n";
        return 0;
    }

    private function signatureTest(int $id, string $file): int
    {
        $s = DB::first('SELECT * FROM malware_signatures WHERE id=?', [$id]);
        if (!$s || !is_file($file)) throw new \InvalidArgumentException('Signature or file not found.');
        $m = ['extension' => strtolower(pathinfo($file, PATHINFO_EXTENSION)), 'sha256' => hash_file('sha256', $file)];
        $hit = (new \App\Modules\Scanner\SignatureEngine())->match($s, $file, basename($file), $m, file_get_contents($file));
        echo json_encode(['matched' => (bool)$hit, 'details' => $hit], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
        return $hit ? 0 : 1;
    }

    private function signatureSweep(int $id): int
    {
        if (!$id) throw new \InvalidArgumentException('signature_id is required.');
        $result = (new \App\Modules\Scanner\SignatureSweepService())->sweep($id);
        echo "Sweep for signature #{$id} ({$result['signature']['name']}): sites_scanned={$result['sites_scanned']} files_scanned={$result['files_scanned']} matches=" . count($result['finding_ids']) . "\n";
        foreach ($result['finding_ids'] as $fid) echo "  finding #$fid\n";
        return 0;
    }

    private function signatureSuggest(int $findingId): int
    {
        $f = DB::first('SELECT * FROM findings WHERE id=?', [$findingId]);
        if (!$f) throw new \InvalidArgumentException('Finding not found.');
        if (!filter_var(env_value('JURA_AI_SIGNATURES_ENABLED', 'false'), FILTER_VALIDATE_BOOLEAN)) {
            $id = DB::insert('INSERT INTO signature_suggestions (finding_id,source_file_path,source_file_sha256,ai_provider,model,status,suggested_name,suggested_risk,suggested_type,suggested_pattern_type,suggested_pattern_json,explanation,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [$findingId,$f['path'],$f['sha256'],env_value('JURA_AI_PROVIDER','openai'),env_value('JURA_AI_MODEL',''),'draft','Draft from finding '.$findingId,$f['risk'],$f['type'],'combo','{}','AI signatures are disabled; draft placeholder created for manual review.',now(),now()]);
            echo "Draft signature suggestion #$id created; not enabled.\n";
            return 0;
        }
        echo "AI provider call is not configured in this build; no API key stored.\n";
        return 1;
    }

    private function ensureRestoreActionsTable(string $driver): void
    {
        if ($driver === 'mysql') DB::pdo()->exec("CREATE TABLE IF NOT EXISTS restore_actions (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, admin_user_id BIGINT UNSIGNED NULL, original_path VARCHAR(2048) NOT NULL, backup_provider VARCHAR(64) NOT NULL, backup_user VARCHAR(255) NULL, backup_date VARCHAR(64) NULL, backup_source_archive TEXT NULL, previous_sha256 CHAR(64) NULL, restored_sha256 CHAR(64) NULL, previous_size BIGINT NULL, restored_size BIGINT NULL, quarantine_path TEXT NULL, created_at DATETIME NULL, status VARCHAR(32) NOT NULL DEFAULT 'pending', error_message TEXT NULL, INDEX restore_actions_path_idx(original_path(191))) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        else DB::pdo()->exec("CREATE TABLE IF NOT EXISTS restore_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_user_id INTEGER NULL, original_path TEXT NOT NULL, backup_provider TEXT NOT NULL, backup_user TEXT NULL, backup_date TEXT NULL, backup_source_archive TEXT NULL, previous_sha256 TEXT NULL, restored_sha256 TEXT NULL, previous_size INTEGER NULL, restored_size INTEGER NULL, quarantine_path TEXT NULL, created_at TEXT, status TEXT NOT NULL DEFAULT 'pending', error_message TEXT NULL)");
    }

    private function ensureThreatIpsTable(string $driver): void
    {
        if ($driver === 'mysql') DB::pdo()->exec("CREATE TABLE IF NOT EXISTS threat_ips (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, ip VARCHAR(64) NOT NULL, classification VARCHAR(32) NOT NULL DEFAULT 'unknown', risk VARCHAR(32) NOT NULL DEFAULT 'medium', notes TEXT NULL, hit_count BIGINT NOT NULL DEFAULT 0, source VARCHAR(32) NOT NULL DEFAULT 'manual', first_seen_at DATETIME NULL, last_seen_at DATETIME NULL, created_at DATETIME NULL, updated_at DATETIME NULL, UNIQUE KEY uniq_threat_ips_ip(ip)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        else DB::pdo()->exec("CREATE TABLE IF NOT EXISTS threat_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL UNIQUE, classification TEXT NOT NULL DEFAULT 'unknown', risk TEXT NOT NULL DEFAULT 'medium', notes TEXT NULL, hit_count INTEGER NOT NULL DEFAULT 0, source TEXT NOT NULL DEFAULT 'manual', first_seen_at TEXT NULL, last_seen_at TEXT NULL, created_at TEXT, updated_at TEXT)");
        $this->ensureColumn('threat_ips', 'confidence', $driver === 'mysql' ? 'VARCHAR(32) NULL' : 'TEXT NULL');
        $this->ensureColumn('threat_ips', 'recommended_action', $driver === 'mysql' ? 'VARCHAR(64) NULL' : 'TEXT NULL');
        $this->ensureColumn('threat_ips', 'incident_id', $driver === 'mysql' ? 'BIGINT NULL' : 'INTEGER NULL');
        $this->ensureColumn('threat_ips', 'blocked_at', $driver === 'mysql' ? 'DATETIME NULL' : 'TEXT NULL');
        $this->ensureColumn('threat_ips', 'firewall_status', $driver === 'mysql' ? 'VARCHAR(32) NULL' : 'TEXT NULL');
        $this->ensureColumn('threat_ips', 'firewall_error', $driver === 'mysql' ? 'TEXT NULL' : 'TEXT NULL');
        if ($driver === 'mysql') { try { DB::pdo()->exec("ALTER TABLE threat_ips MODIFY source VARCHAR(191) NOT NULL DEFAULT 'manual'"); } catch (\Throwable) {} }
    }

    private function ensureThreatIpEvidenceTable(string $driver): void
    {
        if ($driver === 'mysql') {
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS threat_ip_evidence (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, threat_ip_id BIGINT UNSIGNED NOT NULL, log_event_id BIGINT UNSIGNED NULL, site_id BIGINT UNSIGNED NULL, site_name VARCHAR(255) NULL, request_uri LONGTEXT NULL, file_path TEXT NULL, detected_at DATETIME NULL, created_at DATETIME NULL, UNIQUE KEY uniq_threat_ip_log_event(threat_ip_id, log_event_id), INDEX threat_ip_evidence_ip_idx(threat_ip_id), INDEX threat_ip_evidence_event_idx(log_event_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        } else {
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS threat_ip_evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, threat_ip_id INTEGER NOT NULL, log_event_id INTEGER NULL, site_id INTEGER NULL, site_name TEXT NULL, request_uri TEXT NULL, file_path TEXT NULL, detected_at TEXT NULL, created_at TEXT, UNIQUE(threat_ip_id, log_event_id))");
            DB::pdo()->exec('CREATE INDEX IF NOT EXISTS threat_ip_evidence_ip_idx ON threat_ip_evidence(threat_ip_id)');
            DB::pdo()->exec('CREATE INDEX IF NOT EXISTS threat_ip_evidence_event_idx ON threat_ip_evidence(log_event_id)');
        }
    }

    private function ensureIncidentTables(string $driver): void
    {
        if ($driver === 'mysql') {
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS incidents (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, external_id VARCHAR(191) NOT NULL, title VARCHAR(255) NOT NULL, severity VARCHAR(32) NOT NULL DEFAULT 'medium', confidence VARCHAR(32) NULL, status VARCHAR(64) NULL, summary TEXT NULL, server_hostname VARCHAR(255) NULL, timeline_json LONGTEXT NULL, affected_assets_json LONGTEXT NULL, path_indicators_json LONGTEXT NULL, excluded_ips_json LONGTEXT NULL, response_actions_json LONGTEXT NULL, import_policy_json LONGTEXT NULL, raw_json LONGTEXT NULL, source_file VARCHAR(255) NULL, imported_at DATETIME NULL, created_at DATETIME NULL, updated_at DATETIME NULL, UNIQUE KEY uniq_incidents_external_id(external_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS incident_file_iocs (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, incident_id BIGINT UNSIGNED NULL, sha256 CHAR(64) NULL, size BIGINT NULL, names_json LONGTEXT NULL, role VARCHAR(128) NULL, risk VARCHAR(32) NULL, confidence VARCHAR(32) NULL, scope VARCHAR(255) NULL, dedup_key CHAR(64) NULL, created_at DATETIME NULL, updated_at DATETIME NULL, UNIQUE KEY uniq_incident_file_iocs_sha256(sha256), UNIQUE KEY uniq_incident_file_iocs_dedup_key(dedup_key), INDEX incident_file_iocs_incident_id_idx(incident_id), CONSTRAINT incident_file_iocs_incident_fk FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE SET NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        } else {
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, external_id TEXT NOT NULL UNIQUE, title TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'medium', confidence TEXT NULL, status TEXT NULL, summary TEXT NULL, server_hostname TEXT NULL, timeline_json TEXT NULL, affected_assets_json TEXT NULL, path_indicators_json TEXT NULL, excluded_ips_json TEXT NULL, response_actions_json TEXT NULL, import_policy_json TEXT NULL, raw_json TEXT NULL, source_file TEXT NULL, imported_at TEXT NULL, created_at TEXT, updated_at TEXT)");
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS incident_file_iocs (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NULL, sha256 TEXT NULL UNIQUE, size INTEGER NULL, names_json TEXT NULL, role TEXT NULL, risk TEXT NULL, confidence TEXT NULL, scope TEXT NULL, dedup_key TEXT NULL UNIQUE, created_at TEXT, updated_at TEXT)");
        }
        $this->ensureColumn('malware_signatures', 'incident_id', $driver === 'mysql' ? 'BIGINT NULL' : 'INTEGER NULL');
        $this->ensureFileIocSha256Nullable($driver);
        $this->ensureIncidentLinkTables($driver);
        $this->ensureTrustedIpsTable($driver);
        $this->ensureCronMonitorTable($driver);
        $this->ensureNotificationsTable($driver);
    }

    /**
     * incident_file_iocs.sha256 used to be NOT NULL; some incident reports document a file IOC
     * by name/role before its hash has been collected. Relaxes existing installations to match
     * the now-nullable column in the CREATE TABLE definitions above, and backfills dedup_key
     * (the new upsert identity, sha256 when known, otherwise name+size+role) for old rows.
     */
    private function ensureFileIocSha256Nullable(string $driver): void
    {
        if ($driver === 'mysql') {
            try { DB::pdo()->exec('ALTER TABLE incident_file_iocs MODIFY sha256 CHAR(64) NULL'); } catch (\Throwable) {}
            $this->ensureColumn('incident_file_iocs', 'dedup_key', 'CHAR(64) NULL');
            try { DB::pdo()->exec('ALTER TABLE incident_file_iocs ADD UNIQUE KEY uniq_incident_file_iocs_dedup_key(dedup_key)'); } catch (\Throwable) {}
        } else {
            $col = null;
            foreach (DB::select('PRAGMA table_info(incident_file_iocs)') as $c) if ($c['name'] === 'sha256') $col = $c;
            if ($col && (int) $col['notnull'] === 1) {
                DB::pdo()->exec('CREATE TABLE incident_file_iocs_new (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NULL, sha256 TEXT NULL UNIQUE, size INTEGER NULL, names_json TEXT NULL, role TEXT NULL, risk TEXT NULL, confidence TEXT NULL, scope TEXT NULL, dedup_key TEXT NULL UNIQUE, created_at TEXT, updated_at TEXT)');
                DB::pdo()->exec("INSERT INTO incident_file_iocs_new (id,incident_id,sha256,size,names_json,role,risk,confidence,scope,dedup_key,created_at,updated_at) SELECT id,incident_id,sha256,size,names_json,role,risk,confidence,scope,LOWER(sha256),created_at,updated_at FROM incident_file_iocs");
                DB::pdo()->exec('DROP TABLE incident_file_iocs');
                DB::pdo()->exec('ALTER TABLE incident_file_iocs_new RENAME TO incident_file_iocs');
            }
            $this->ensureColumn('incident_file_iocs', 'dedup_key', 'TEXT NULL');
        }
        DB::pdo()->exec('UPDATE incident_file_iocs SET dedup_key = LOWER(sha256) WHERE dedup_key IS NULL AND sha256 IS NOT NULL');
    }

    private function ensureTrustedIpsTable(string $driver): void
    {
        if ($driver === 'mysql') DB::pdo()->exec("CREATE TABLE IF NOT EXISTS trusted_ips (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, ip VARCHAR(64) NOT NULL, label VARCHAR(255) NULL, notes TEXT NULL, created_at DATETIME NULL, updated_at DATETIME NULL, UNIQUE KEY uniq_trusted_ips_ip(ip)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        else DB::pdo()->exec("CREATE TABLE IF NOT EXISTS trusted_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL UNIQUE, label TEXT NULL, notes TEXT NULL, created_at TEXT, updated_at TEXT)");
    }

    private function ensureCronMonitorTable(string $driver): void
    {
        if ($driver === 'mysql') DB::pdo()->exec("CREATE TABLE IF NOT EXISTS cron_snapshots (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id BIGINT UNSIGNED NULL, server_user VARCHAR(255) NOT NULL, line TEXT NOT NULL, line_hash CHAR(64) NOT NULL, is_missing TINYINT(1) NOT NULL DEFAULT 0, first_seen_at DATETIME NULL, last_seen_at DATETIME NULL, notified_at DATETIME NULL, created_at DATETIME NULL, updated_at DATETIME NULL, UNIQUE KEY uniq_cron_snapshots_user_line(server_user, line_hash), INDEX cron_snapshots_user_id_idx(user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        else DB::pdo()->exec("CREATE TABLE IF NOT EXISTS cron_snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NULL, server_user TEXT NOT NULL, line TEXT NOT NULL, line_hash TEXT NOT NULL, is_missing INTEGER NOT NULL DEFAULT 0, first_seen_at TEXT NULL, last_seen_at TEXT NULL, notified_at TEXT NULL, created_at TEXT, updated_at TEXT, UNIQUE(server_user, line_hash))");
    }

    private function ensureNotificationsTable(string $driver): void
    {
        if ($driver === 'mysql') DB::pdo()->exec("CREATE TABLE IF NOT EXISTS notifications_log (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, channel VARCHAR(32) NOT NULL DEFAULT 'telegram', category VARCHAR(64) NOT NULL, message TEXT NOT NULL, related_type VARCHAR(64) NULL, related_id BIGINT NULL, status VARCHAR(32) NOT NULL DEFAULT 'sent', error_text TEXT NULL, created_at DATETIME NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        else DB::pdo()->exec("CREATE TABLE IF NOT EXISTS notifications_log (id INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT NOT NULL DEFAULT 'telegram', category TEXT NOT NULL, message TEXT NOT NULL, related_type TEXT NULL, related_id INTEGER NULL, status TEXT NOT NULL DEFAULT 'sent', error_text TEXT NULL, created_at TEXT)");
    }

    private function ensureIncidentLinkTables(string $driver): void
    {
        // incident_id on threat_ips/malware_signatures/incident_file_iocs only tracks the most
        // recently importing incident. The same IP, signature, or hash can legitimately belong to
        // multiple incidents, so these join tables are the actual source of truth for "what belongs
        // to this incident" on the incident detail page.
        if ($driver === 'mysql') {
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS incident_threat_ip_links (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, incident_id BIGINT UNSIGNED NOT NULL, threat_ip_id BIGINT UNSIGNED NOT NULL, created_at DATETIME NULL, UNIQUE KEY uniq_incident_threat_ip(incident_id, threat_ip_id), INDEX incident_threat_ip_links_threat_ip_idx(threat_ip_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS incident_signature_links (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, incident_id BIGINT UNSIGNED NOT NULL, signature_id BIGINT UNSIGNED NOT NULL, created_at DATETIME NULL, UNIQUE KEY uniq_incident_signature(incident_id, signature_id), INDEX incident_signature_links_signature_idx(signature_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS incident_file_ioc_links (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, incident_id BIGINT UNSIGNED NOT NULL, file_ioc_id BIGINT UNSIGNED NOT NULL, created_at DATETIME NULL, UNIQUE KEY uniq_incident_file_ioc(incident_id, file_ioc_id), INDEX incident_file_ioc_links_ioc_idx(file_ioc_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        } else {
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS incident_threat_ip_links (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, threat_ip_id INTEGER NOT NULL, created_at TEXT, UNIQUE(incident_id, threat_ip_id))");
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS incident_signature_links (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, signature_id INTEGER NOT NULL, created_at TEXT, UNIQUE(incident_id, signature_id))");
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS incident_file_ioc_links (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, file_ioc_id INTEGER NOT NULL, created_at TEXT, UNIQUE(incident_id, file_ioc_id))");
        }
    }

    private function ensureAiChatTable(string $driver): void
    {
        if ($driver === 'mysql') DB::pdo()->exec("CREATE TABLE IF NOT EXISTS ai_chat_messages (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, admin_user_id BIGINT UNSIGNED NULL, role VARCHAR(32) NOT NULL, content LONGTEXT NULL, tool_name VARCHAR(128) NULL, tool_arguments_json LONGTEXT NULL, tool_status VARCHAR(32) NULL, tool_result LONGTEXT NULL, created_at DATETIME NULL, INDEX ai_chat_messages_admin_user_idx(admin_user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        else DB::pdo()->exec("CREATE TABLE IF NOT EXISTS ai_chat_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_user_id INTEGER NULL, role TEXT NOT NULL, content TEXT NULL, tool_name TEXT NULL, tool_arguments_json TEXT NULL, tool_status TEXT NULL, tool_result TEXT NULL, created_at TEXT)");
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
        $options = $this->scanOptions($argv);
        if ($scope === 'site') $this->validateScanSitePath($value);
        $lock = new ScanLock();
        $lockLabel = $this->optionString($argv, '--lock-label') ?? implode(' ', array_slice($argv, 1));
        if (!$options['no_lock']) $lock->acquire($lockLabel, $options['force']);
        try { $id=(new ScannerService())->scan($scope,$value,$options); echo "Scan run #$id completed.\n"; return 0; }
        finally { if (!$options['no_lock']) $lock->release(); }
    }

    private function validateScanSitePath(?string $path): void
    {
        if (!$path) throw new \InvalidArgumentException('Site path is required.');
        $real = realpath($path);
        if ($real === false || !is_dir($real)) throw new \InvalidArgumentException("scan-site path does not exist or is not a directory: {$path}");
        return;
    }

    private function logs(array $argv): int { $o=$this->scanOptions($argv); $n=(new LogAnalyzerService())->analyze(['no_lock'=>$o['no_lock'],'force'=>$o['force']]); echo "Stored suspicious log events: $n\n"; return 0; }
    private function scanOptions(array $argv): array {
        $this->validateOptions($argv, ['--profile','--force','--no-lock','--include-old','--include-storage','--include-backups','--include-vendor','--dry-run','--verbose','--max-files','--max-seconds','--diff','--changed-only','--full-rescan','--skip-logs','--include-logs','--lock-label','--paranoid']);
        return ['profile'=>$this->optionString($argv,'--profile') ?? (string)config('guard.scan_profile','fast'), 'force'=>in_array('--force',$argv,true), 'no_lock'=>in_array('--no-lock',$argv,true), 'include_old'=>in_array('--include-old',$argv,true), 'include_storage'=>in_array('--include-storage',$argv,true), 'include_backups'=>in_array('--include-backups',$argv,true), 'include_vendor'=>in_array('--include-vendor',$argv,true), 'dry_run'=>in_array('--dry-run',$argv,true), 'verbose'=>in_array('--verbose',$argv,true), 'max_files'=>$this->optionInt($argv,'--max-files'), 'max_seconds'=>$this->optionInt($argv,'--max-seconds'), 'diff'=>in_array('--diff',$argv,true), 'changed_only'=>in_array('--changed-only',$argv,true), 'full_rescan'=>in_array('--full-rescan',$argv,true), 'skip_logs'=>in_array('--skip-logs',$argv,true), 'include_logs'=>in_array('--include-logs',$argv,true), 'paranoid'=>in_array('--paranoid',$argv,true)]; }
    private function validateOptions(array $argv, array $allowed): void { foreach (array_slice($argv, 2) as $arg) { if (!str_starts_with($arg, '--')) continue; $name = explode('=', $arg, 2)[0]; if (!in_array($name, $allowed, true)) throw new \InvalidArgumentException("Unsupported option: $name"); } }
    private function optionInt(array $argv, string $name): ?int { foreach($argv as $a) if(str_starts_with($a,$name.'=')) return (int)substr($a,strlen($name)+1); return null; }
    private function optionString(array $argv, string $name): ?string { foreach($argv as $a) if(str_starts_with($a,$name.'=')) return substr($a,strlen($name)+1); return null; }

    private function scanActive(): int
    {
        if (DB::first("SELECT id FROM scan_runs WHERE status='running' AND total_files_estimated > 0 AND files_scanned >= total_files_estimated LIMIT 1")) { DB::statement("UPDATE scan_runs SET status='completed', finished_at=?, error_text=?, last_heartbeat_at=?, progress_message=?, updated_at=? WHERE status='running' AND total_files_estimated > 0 AND files_scanned >= total_files_estimated", [now(), 'Auto-completed by guard:scan-active because progress reached 100%', now(), 'Auto-completed stale 100% scan', now()]); (new ScanLock())->unlock(true); }
        $lock = (new ScanLock())->read();
        $run = DB::first("SELECT * FROM scan_runs WHERE status='running' AND NOT (total_files_estimated > 0 AND files_scanned >= total_files_estimated) ORDER BY id DESC LIMIT 1") ?: [];
        $running = (bool)$lock || (bool)$run;
        echo "Scan running: ".($running ? 'yes' : 'no')."\n";
        if (!$running) return 0;
        $pid = (int)($run['pid'] ?? $lock['pid'] ?? 0);
        $started = $run['started_at'] ?? $lock['started_at'] ?? null;
        $lastHeartbeat = $run['last_heartbeat_at'] ?? null;
        $heartbeatAge = $lastHeartbeat ? max(0, time() - $this->utcTimestamp($lastHeartbeat)) : null;
        $pidAlive = $pid > 0 && $this->pidAlive($pid);
        $stale = (bool)$run && ((!$pidAlive && $pid > 0) || ($heartbeatAge !== null && $heartbeatAge > 90));
        $elapsed = $started ? $this->formatSeconds(max(0, time() - $this->utcTimestamp($started))) : 'n/a';
        $files = (int)($run['files_scanned'] ?? 0);
        $total = (int)($run['total_files_estimated'] ?? 0);
        $progress = $total > 0 ? round($files * 100 / $total, 1).'%' : 'unknown';
        echo "PID: ".($pid ?: 'n/a')."\n";
        echo "PID alive: ".($pidAlive ? 'yes' : 'no')."\n";
        echo "scan_run id: ".($run['id'] ?? 'n/a')."\n";
        echo "profile: ".($run['profile'] ?? 'n/a')."\n";
        echo "scope: ".(($run['scope_type'] ?? 'n/a').(isset($run['scope_value']) && $run['scope_value'] !== null ? ' '.$run['scope_value'] : ''))."\n";
        echo "files scanned: ".$files."\n";
        echo "total estimated: ".($total ?: 'unknown')."\n";
        echo "progress: $progress\n";
        echo "skipped media: ".($run['skipped_media'] ?? 0)."\n";
        echo "skipped directories: ".($run['skipped_directories'] ?? 0)."\n";
        echo "findings: ".($run['findings_count'] ?? 0)."\n";
        echo "new findings: ".($run['findings_new'] ?? 0)."\n";
        echo "current site: ".($run['current_site'] ?? 'n/a')."\n";
        echo "current path: ".($run['current_path'] ?? 'n/a')."\n";
        echo "started_at: ".($started ?? 'n/a')."\n";
        echo "last heartbeat: ".($lastHeartbeat ?? 'n/a')."\n";
        echo "heartbeat age: ".($heartbeatAge !== null ? $heartbeatAge.'s' : 'n/a')."\n";
        echo "elapsed time: $elapsed\n";
        echo "stale: ".($stale ? 'yes' : 'no')."\n";
        if ($lock) echo "lock: ".($lock['command'] ?? 'unknown')."\n";
        return 0;
    }

    private function utcTimestamp(string $timestamp): int { return strtotime($timestamp . ' UTC') ?: strtotime($timestamp) ?: time(); }

    private function pidAlive(int $pid): bool { return $pid > 0 && (function_exists('posix_kill') ? @posix_kill($pid, 0) : is_dir('/proc/'.$pid)); }

    private function formatSeconds(int $seconds): string
    {
        return sprintf('%02d:%02d:%02d', intdiv($seconds, 3600), intdiv($seconds % 3600, 60), $seconds % 60);
    }

    private function scanUnlock(array $argv): int { echo (new ScanLock())->unlock(in_array('--force',$argv,true))."\n"; return 0; }
    private function cleanupRunningScans(array $argv): int { $h=$this->optionInt($argv,'--hours') ?? 2; DB::statement("UPDATE scan_runs SET status='completed', finished_at=?, error_text=?, last_heartbeat_at=?, progress_message=?, updated_at=? WHERE status='running' AND total_files_estimated > 0 AND files_scanned >= total_files_estimated", [now(), 'Marked completed by cleanup: stale run had reached 100%', now(), 'Cleanup completed stale 100% scan', now()]); DB::statement("UPDATE scan_runs SET status='failed', finished_at=?, error_text=?, updated_at=? WHERE status='running' AND started_at < ".DB::nowMinusHoursSql($h), [now(), "Marked failed by cleanup after {$h} hours", now()]); (new ScanLock())->unlock(true); echo "Old running scan_runs cleaned up.\n"; return 0; }
    private function prune(array $argv): int { $d=$this->optionInt($argv,'--days') ?? 30; $cut=gmdate('Y-m-d H:i:s', time()-$d*86400); foreach(['log_events','scan_runs'] as $t) DB::statement("DELETE FROM $t WHERE created_at < ?",[$cut]); DB::statement("DELETE FROM file_snapshots WHERE is_missing=1 AND updated_at < ?",[$cut]); echo "Pruned data older than $d days.\n"; return 0; }
    private function dbStats(): int { echo "DB driver: ".DB::driver()."\n"; foreach(['users','sites','file_snapshots','findings','log_events','scan_runs'] as $t) echo "$t: ".(DB::first("SELECT COUNT(*) c FROM $t")['c']??0)."\n"; if(DB::driver()==='sqlite') echo "DB size: ".(is_file(DB::path()) ? filesize(DB::path()) : 0)." bytes\n"; else foreach(DB::select('SELECT table_name, table_rows, ROUND((data_length+index_length)/1024/1024,2) mb FROM information_schema.tables WHERE table_schema=DATABASE() ORDER BY (data_length+index_length) DESC LIMIT 10') as $r) echo "{$r['table_name']}: {$r['table_rows']} rows, {$r['mb']} MB\n"; return 0; }
    private function optimizeDb(): int { if(DB::driver()==='sqlite') { DB::pdo()->exec('VACUUM'); DB::pdo()->exec('ANALYZE'); } else foreach(['admin_users','users','sites','scan_runs','file_snapshots','findings','log_events','quarantine_items','rules','allowlist_rules','settings','ai_analyses'] as $t) DB::pdo()->exec("OPTIMIZE TABLE $t"); echo "Database optimized.\n"; return 0; }
    private function quarantine(int $id): int { if(!$id) throw new \InvalidArgumentException('finding_id is required.'); $qid=(new QuarantineService())->quarantine($id); echo "Quarantined as item #$qid\n"; return 0; }
    private function restore(int $id): int { if(!$id) throw new \InvalidArgumentException('quarantine_id is required.'); (new QuarantineService())->restore($id); echo "Restored quarantine item #$id\n"; return 0; }
    private function bulkFindingsAction(string $id): int { if($id==='') throw new \InvalidArgumentException('bulk_action_id is required.'); $state=(new BulkFindingActionService())->run($id); echo "Bulk {$state['action']} {$state['status']}: {$state['processed']}/{$state['total']}, ok={$state['ok']}, fail={$state['fail']}\n"; return $state['status']==='completed'?0:1; }

    private function backupDetect(): int { $d=(new IspmanagerBackupService())->detectTools(); echo "Backup root exists: ".($d['root_exists']?'yes':'no')."\nISPmanager /usr/local/mgr5: ".($d['mgr5_exists']?'yes':'no')."\nTools:\n".implode("\n", $d['tools'])."\n"; return 0; }
    private function backupUsers(): int { foreach((new IspmanagerBackupService())->users() as $u) echo $u."\n"; return 0; }
    private function backupList(array $argv): int { foreach((new IspmanagerBackupService())->backups($this->optionString($argv,'--user')) as $b) echo "{$b['user']}\t{$b['date']}\t{$b['type']}\t{$b['path']}\n"; return 0; }
    private function backupFind(array $argv): int { $path=$this->optionString($argv,'--path') ?? throw new \InvalidArgumentException('--path required'); foreach((new IspmanagerBackupService())->findFile($path) as $f) echo "{$f['date']}\t{$f['backup_type']}\t{$f['source']}\t{$f['size']}\n"; return 0; }
    private function backupPreview(array $argv): int { echo (new IspmanagerBackupService())->preview($this->optionString($argv,'--path') ?? throw new \InvalidArgumentException('--path required'), $this->optionString($argv,'--date') ?? throw new \InvalidArgumentException('--date required')); return 0; }
    private function backupDiff(array $argv): int { echo (new IspmanagerBackupService())->diff($this->optionString($argv,'--path') ?? throw new \InvalidArgumentException('--path required'), $this->optionString($argv,'--date') ?? throw new \InvalidArgumentException('--date required'))."\n"; return 0; }
    private function backupRestore(array $argv): int { $id=(new IspmanagerBackupService())->restore($this->optionString($argv,'--path') ?? throw new \InvalidArgumentException('--path required'), $this->optionString($argv,'--date') ?? throw new \InvalidArgumentException('--date required')); echo "Restore action #$id completed.\n"; return 0; }


    private function sites(): int
    {
        echo "server_user\tsite\tpath\tcms\tversion\tconfidence\tnotes\n";
        foreach (DB::select('SELECT u.name AS server_user, s.name AS site, s.path, s.cms_type, s.cms_version, s.cms_confidence, s.cms_notes FROM sites s LEFT JOIN users u ON u.id = s.server_user_id ORDER BY u.name, s.name') as $r) {
            echo ($r['server_user'] ?? '')."\t{$r['site']}\t{$r['path']}\t".($r['cms_type'] ?? '')."\t".($r['cms_version'] ?? '')."\t".($r['cms_confidence'] ?? '')."\t".($r['cms_notes'] ?? '')."\n";
        }
        return 0;
    }

    private function status(): int { $last=DB::first('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1')?:[]; $users=DB::first('SELECT COUNT(*) c FROM users')['c']??0; $sites=DB::first('SELECT COUNT(*) c FROM sites')['c']??0; $find=DB::first("SELECT COUNT(*) c FROM findings WHERE status='new'")['c']??0; echo "Jura Server Guard status\nDB: ".DB::driver()."\nUsers: $users\nSites: $sites\nNew findings: $find\nLast scan: ".($last['started_at']??'never')." (".($last['status']??'n/a').")\n"; return 0; }

    private function ipList(): int { echo "ip\tclassification\trisk\thit_count\tfirst_seen_at\tlast_seen_at\tnotes\n"; foreach (DB::select('SELECT * FROM threat_ips ORDER BY updated_at DESC') as $r) echo "{$r['ip']}\t{$r['classification']}\t{$r['risk']}\t{$r['hit_count']}\t{$r['first_seen_at']}\t{$r['last_seen_at']}\t".str_replace(["\t","\n"],' ',(string)$r['notes'])."\n"; return 0; }
    private function ipAdd(array $argv): int {
        $ip = trim((string)($argv[2] ?? '')); if ($ip === '') throw new \InvalidArgumentException('ip is required.');
        $classification = $this->optionString($argv, '--classification') ?? 'unknown';
        $risk = $this->optionString($argv, '--risk') ?? 'medium';
        $notes = $this->optionString($argv, '--notes') ?? '';
        $this->upsertThreatIp($ip, $classification, $risk, $notes, 'cli');
        echo "Recorded threat IP $ip ($classification, $risk).\n";
        return 0;
    }
    private function ipRemove(array $argv): int { $ip = trim((string)($argv[2] ?? '')); if ($ip === '') throw new \InvalidArgumentException('ip is required.'); DB::statement('DELETE FROM threat_ips WHERE ip=?', [$ip]); echo "Removed $ip from threat IPs.\n"; return 0; }
    private function upsertThreatIp(string $ip, string $classification, string $risk, string $notes, string $source): void {
        $existing = DB::first('SELECT id,hit_count,first_seen_at FROM threat_ips WHERE ip=?', [$ip]);
        if ($existing) DB::statement('UPDATE threat_ips SET classification=?, risk=?, notes=?, hit_count=?, last_seen_at=?, updated_at=? WHERE id=?', [$classification, $risk, $notes, (int)$existing['hit_count'] + 1, now(), now(), $existing['id']]);
        else DB::insert('INSERT INTO threat_ips (ip,classification,risk,notes,hit_count,source,first_seen_at,last_seen_at,created_at,updated_at) VALUES (?,?,?,?,1,?,?,?,?,?)', [$ip, $classification, $risk, $notes, $source, now(), now(), now(), now()]);
    }

    private function findHash(array $argv): int {
        $hash = strtolower(trim((string)($argv[2] ?? ''))); if ($hash === '') throw new \InvalidArgumentException('sha256 is required.');
        $rows = DB::select('SELECT fs.path, fs.is_missing, fs.last_seen_at, s.name site_name, u.name user_name FROM file_snapshots fs LEFT JOIN sites s ON s.id=fs.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE fs.sha256=? ORDER BY fs.last_seen_at DESC LIMIT 200', [$hash]);
        if (!$rows) { echo "No files with sha256=$hash found in file_snapshots.\n"; return 0; }
        echo "user\tsite\tpath\tmissing\tlast_seen_at\n";
        foreach ($rows as $r) echo ($r['user_name'] ?? '')."\t".($r['site_name'] ?? '')."\t{$r['path']}\t".($r['is_missing'] ? 'yes' : 'no')."\t{$r['last_seen_at']}\n";
        return 0;
    }

    private function incidentImport(array $argv): int {
        $path = $argv[2] ?? null;
        if (!$path || !is_file($path)) throw new \InvalidArgumentException('Path to an incident JSON file is required.');
        $data = json_decode((string) file_get_contents($path), true);
        if (!is_array($data)) throw new \InvalidArgumentException('File is not valid JSON.');
        $dryRun = in_array('--dry-run', $argv, true);
        $result = (new IncidentImportService())->import($data, $dryRun, basename($path));
        if (!$result['ok']) { fwrite(STDERR, "Import rejected:\n - " . implode("\n - ", $result['errors']) . "\n"); return 1; }
        $s = $result['summary'];
        echo ($dryRun ? "[dry-run] " : '') . "Incident {$s['incident_external_id']} ({$s['incident_action']}): " .
            "threat_ips created={$s['threat_ips']['created']} updated={$s['threat_ips']['updated']}, " .
            "signatures created={$s['signatures']['created']} updated={$s['signatures']['updated']}, " .
            "file_iocs created={$s['file_iocs']['created']} updated={$s['file_iocs']['updated']}, " .
            "excluded_ips_recorded={$s['excluded_ips_recorded']}\n";
        if (!$dryRun) echo "Incident id: {$s['incident_id']}. View at /incidents/{$s['incident_id']}\n";
        return 0;
    }

    private function incidentList(): int {
        echo "id\texternal_id\tseverity\tstatus\ttitle\timported_at\n";
        foreach (DB::select('SELECT id,external_id,severity,status,title,imported_at FROM incidents ORDER BY imported_at DESC') as $r) {
            echo "{$r['id']}\t{$r['external_id']}\t{$r['severity']}\t".($r['status'] ?? '')."\t{$r['title']}\t{$r['imported_at']}\n";
        }
        return 0;
    }

    private function trustIp(array $argv): int {
        $ip = trim((string)($argv[2] ?? '')); if ($ip === '') throw new \InvalidArgumentException('ip is required.');
        $label = $this->optionString($argv, '--label') ?? '';
        $notes = $this->optionString($argv, '--notes') ?? '';
        $existing = DB::first('SELECT id FROM trusted_ips WHERE ip=?', [$ip]);
        if ($existing) DB::statement('UPDATE trusted_ips SET label=?,notes=?,updated_at=? WHERE id=?', [$label,$notes,now(),$existing['id']]);
        else DB::insert('INSERT INTO trusted_ips (ip,label,notes,created_at,updated_at) VALUES (?,?,?,?,?)', [$ip,$label,$notes,now(),now()]);
        echo "Trusted IP $ip saved.\n";
        return 0;
    }
    private function untrustIp(array $argv): int { $ip = trim((string)($argv[2] ?? '')); if ($ip === '') throw new \InvalidArgumentException('ip is required.'); DB::statement('DELETE FROM trusted_ips WHERE ip=?', [$ip]); echo "Removed $ip from trusted IPs.\n"; return 0; }
    private function trustedIpsList(): int {
        echo "ip\tlabel\tnotes\tcreated_at\n";
        foreach (DB::select('SELECT * FROM trusted_ips ORDER BY ip') as $r) echo "{$r['ip']}\t".($r['label']??'')."\t".str_replace(["\t","\n"],' ',(string)$r['notes'])."\t{$r['created_at']}\n";
        return 0;
    }

    private function cronScan(): int {
        $new = (new AlertService())->runCronCheck();
        echo "Cron scan complete. New entries: " . count($new) . "\n";
        foreach ($new as $entry) echo "  [{$entry['server_user']}] {$entry['line']}\n";
        return 0;
    }

    private function telegramTest(array $argv): int {
        $notifier = new TelegramNotifier();
        if (!$notifier->enabled()) { fwrite(STDERR, "Telegram is disabled or not fully configured (JURA_TELEGRAM_ENABLED/JURA_TELEGRAM_BOT_TOKEN/JURA_TELEGRAM_CHAT_ID).\n"); return 1; }
        $message = $this->optionString($argv, '--message') ?? 'Jura Server Guard: test notification.';
        $result = $notifier->send($message);
        if ($result['ok']) { echo "Sent.\n"; return 0; }
        fwrite(STDERR, "Failed: {$result['error']}\n");
        return 1;
    }

    private function telegramFindings(array $argv): int {
        $runId = (int)($argv[2] ?? 0);
        if ($runId < 1) $runId = (int)(DB::first("SELECT id FROM scan_runs WHERE status IN ('completed','completed_with_limit') ORDER BY id DESC LIMIT 1")['id'] ?? 0);
        if ($runId < 1) { fwrite(STDERR,"No completed scan run found.\n"); return 1; }
        (new AlertService())->sendScanNotifications($runId);
        echo "Telegram finding summaries processed for scan #{$runId}. Check notifications_log for delivery status.\n";
        return 0;
    }
}
