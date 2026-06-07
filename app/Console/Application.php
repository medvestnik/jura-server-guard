<?php
namespace App\Console;

use App\Modules\LogAnalyzer\LogAnalyzerService; use App\Modules\Quarantine\QuarantineService; use App\Modules\Rules\RuleRepository; use App\Modules\Scanner\ScannerService; use App\Support\DB;

class Application
{
    public function run(array $argv): int
    {
        $cmd = $argv[1] ?? 'list';
        try {
            return match ($cmd) {
                'serve' => $this->serve($argv), 'migrate' => $this->migrate(), 'guard:seed-rules' => $this->seedRules(), 'guard:create-admin' => $this->createAdmin($argv[2] ?? env_value('JURA_ADMIN_EMAIL','admin@example.com'), $argv[3] ?? bin2hex(random_bytes(12))),
                'guard:scan' => $this->scan('full', null), 'guard:scan-user' => $this->scan('user', $argv[2] ?? null), 'guard:scan-site' => $this->scan('site', $argv[2] ?? null), 'guard:logs' => $this->logs(), 'guard:quarantine' => $this->quarantine((int)($argv[2] ?? 0)), 'guard:restore' => $this->restore((int)($argv[2] ?? 0)), 'guard:status' => $this->status(), 'key:generate','config:cache','package:discover' => $this->noop($cmd), default => $this->help()
            };
        } catch (\Throwable $e) { fwrite(STDERR, "ERROR: {$e->getMessage()}\n"); return 1; }
    }
    private function help(): int { echo "Jura Server Guard artisan commands:\n  guard:scan\n  guard:scan-user {user}\n  guard:scan-site {path}\n  guard:logs\n  guard:quarantine {finding_id}\n  guard:restore {quarantine_id}\n  guard:status\n  migrate\n  serve --host=127.0.0.1 --port=8765\n"; return 0; }
    private function noop(string $cmd): int { if ($cmd==='key:generate') $this->ensureKey(); echo "$cmd complete.\n"; return 0; }
    private function ensureKey(): void { $env=base_path('.env'); if (!is_file($env) && is_file(base_path('.env.example'))) copy(base_path('.env.example'), $env); if (is_file($env)) { $c=file_get_contents($env); if (preg_match('/^APP_KEY=\s*$/m',$c)) file_put_contents($env,preg_replace('/^APP_KEY=\s*$/m','APP_KEY=base64:'.base64_encode(random_bytes(32)),$c)); } }
    private function serve(array $argv): int
    {
        $host = '127.0.0.1';
        $port = '8765';

        foreach ($argv as $a) {
            if (str_starts_with($a, '--host=')) $host = substr($a, 7);
            if (str_starts_with($a, '--port=')) $port = substr($a, 7);
        }

        $phpBinary = $this->phpBinaryForServer();
        passthru(sprintf('%s -S %s:%s -t %s %s', escapeshellarg($phpBinary), escapeshellarg($host), escapeshellarg($port), escapeshellarg(base_path('public')), escapeshellarg(base_path('public/index.php'))), $code);

        return (int) $code;
    }

    private function phpBinaryForServer(): string
    {
        $configured = trim((string) env_value('JURA_PHP_BIN', ''));

        if ($configured !== '' && is_executable($configured)) {
            return $configured;
        }

        return PHP_BINARY;
    }
    private function migrate(): int { foreach (glob(base_path('database/migrations/*.sql')) ?: [] as $file) DB::pdo()->exec(file_get_contents($file)); (new RuleRepository())->seedDefaults(); echo "Migrated SQLite database: ".DB::path()."\n"; return 0; }
    private function seedRules(): int { (new RuleRepository())->seedDefaults(); echo "Default rules and allowlist seeded.\n"; return 0; }
    private function createAdmin(string $email, string $password): int { $hash=password_hash($password,PASSWORD_DEFAULT); if(DB::first('SELECT id FROM admin_users WHERE email=?',[$email])) DB::statement('UPDATE admin_users SET password_hash=?,updated_at=? WHERE email=?',[$hash,now(),$email]); else DB::insert('INSERT INTO admin_users (email,password_hash,created_at,updated_at) VALUES (?,?,?,?)',[$email,$hash,now(),now()]); echo "Admin login: $email\nAdmin password: $password\n"; return 0; }
    private function scan(string $scope, ?string $value): int { if ($scope !== 'full' && !$value) throw new \InvalidArgumentException('Scope value is required.'); $id=(new ScannerService())->scan($scope,$value); echo "Scan run #$id completed.\n"; return 0; }
    private function logs(): int { $n=(new LogAnalyzerService())->analyze(); echo "Stored suspicious log events: $n\n"; return 0; }
    private function quarantine(int $id): int { if(!$id) throw new \InvalidArgumentException('finding_id is required.'); $qid=(new QuarantineService())->quarantine($id); echo "Quarantined as item #$qid\n"; return 0; }
    private function restore(int $id): int { if(!$id) throw new \InvalidArgumentException('quarantine_id is required.'); (new QuarantineService())->restore($id); echo "Restored quarantine item #$id\n"; return 0; }
    private function status(): int { $last=DB::first('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1')?:[]; $users=DB::first('SELECT COUNT(*) c FROM users')['c']??0; $sites=DB::first('SELECT COUNT(*) c FROM sites')['c']??0; $find=DB::first("SELECT COUNT(*) c FROM findings WHERE status='new'")['c']??0; echo "Jura Server Guard status\nUsers: $users\nSites: $sites\nNew findings: $find\nLast scan: ".($last['started_at']??'never')." (".($last['status']??'n/a').")\n"; return 0; }
}
