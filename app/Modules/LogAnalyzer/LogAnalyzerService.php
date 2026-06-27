<?php
namespace App\Modules\LogAnalyzer;

use App\Support\DB;

class LogAnalyzerService
{
    private int $skippedInserts = 0;
    public function analyze(array $options = []): int
    {
        $count = 0; $this->skippedInserts = 0;
        foreach (config('guard.log_paths') as $pattern) foreach (glob($pattern) ?: [] as $log) {
            if ($this->deadlineReached($options)) break 2;
            if (!$this->logMatchesSiteScope($log, $options['site_paths'] ?? [])) continue;
            $count += $this->analyzeFile($log, $options);
        }
        if ($this->skippedInserts > 0) fwrite(STDERR, "Skipped log events due to DB insert errors: {$this->skippedInserts}\n");
        return $count;
    }
    private function analyzeFile(string $path, array $options = []): int
    {
        if (!is_readable($path)) return 0;
        $lines = @file($path, FILE_IGNORE_NEW_LINES) ?: []; $count = 0; $start = max(0, count($lines) - 5000);
        for ($i=$start; $i<count($lines); $i++) {
            if ($this->deadlineReached($options)) break;
            if ($i % 500 === 0 && isset($options['heartbeat']) && is_callable($options['heartbeat'])) $options['heartbeat']();
            $parsed = $this->parse($lines[$i]); $event = $this->classify($parsed, $lines[$i]);
            if (!$event) continue;
            if (DB::first('SELECT id FROM log_events WHERE log_path=? AND line_number=? AND raw_line=?', [$path, $i+1, $lines[$i]])) continue;
            $uriHash = $parsed['uri'] !== null ? hash('sha256', $parsed['uri']) : null;
            try {
                DB::insert('INSERT INTO log_events (site_id,log_path,line_number,ip,method,uri,uri_hash,status_code,user_agent,referer,event_type,risk,raw_line,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [null,$path,$i+1,$parsed['ip'],$parsed['method'],$parsed['uri'],$uriHash,$parsed['status'],$parsed['ua'],$parsed['referer'],$event['type'],$event['risk'],$lines[$i],$parsed['timestamp'] ?? now(),now()]);
                $count++;
            } catch (\Throwable $e) {
                $this->skippedInserts++;
                fwrite(STDERR, 'Skipped log event insert for '. $path . ':' . ($i+1) . ' - ' . $e->getMessage() . PHP_EOL);
                continue;
            }
        }
        return $count;
    }
    private function deadlineReached(array $options): bool { return !empty($options['deadline_at']) && time() >= (int)$options['deadline_at']; }
    private function logMatchesSiteScope(string $log, array $sitePaths): bool { if (!$sitePaths) return true; foreach ($sitePaths as $path) { $site = basename((string)$path); if ($site !== '' && str_contains($log, $site)) return true; } return false; }
    private function parse(string $line): array
    {
        $out = ['ip'=>null,'method'=>null,'uri'=>null,'status'=>null,'ua'=>null,'referer'=>null,'timestamp'=>null];
        if (preg_match('/^(\d{4})\/(\d{2})\/(\d{2})\s+(\d{2}:\d{2}:\d{2})/', $line, $tm)) $out['timestamp'] = "{$tm[1]}-{$tm[2]}-{$tm[3]} {$tm[4]}";
        if (preg_match('/^(\S+) .*? \"([A-Z]+) ([^\"]+) HTTP\/[^\"]+\" (\d{3}) \S+ \"([^\"]*)\" \"([^\"]*)\"/', $line, $m)) return ['ip'=>$m[1],'method'=>$m[2],'uri'=>$m[3],'status'=>(int)$m[4],'referer'=>$m[5] !== '-' ? $m[5] : null,'ua'=>$m[6] !== '-' ? $m[6] : null,'timestamp'=>$out['timestamp']];
        if (preg_match('/client:\s*([0-9a-f:.]+)/i', $line, $m)) $out['ip'] = $m[1];
        if (preg_match('/request:\s*\"?([A-Z]+)\s+([^\s\"]+)/i', $line, $m)) { $out['method'] = strtoupper($m[1]); $out['uri'] = $m[2]; }
        if (preg_match('/^(?!\d{4}\/\d{2}\/\d{2})(\S+).*?(GET|POST|HEAD)\s+(\S+)/i', $line, $m)) return ['ip'=>$out['ip'] ?: $m[1],'method'=>strtoupper($m[2]),'uri'=>$m[3],'status'=>null,'ua'=>null,'referer'=>null,'timestamp'=>$out['timestamp']];
        return $out;
    }
    private function classify(array $p, string $raw): ?array
    {
        $hay = strtolower(($p['uri'] ?? '') . ' ' . ($p['referer'] ?? '') . ' ' . $raw);
        foreach (['delivery.png','Delivery.png','header-delivery.svg','/ua/delivery','/ru/delivery','/delivery','edelivery'] as $safe) if (str_contains($hay, strtolower($safe))) return null;
        $high = ['?delivery','?deploy=true','?_bh_chk','fileloc=','alfa_data','alfacgiapi','authcontrolier.php','access.policy.php','session.manage.php','field.api.php','whewr.php'];
        foreach ($high as $needle) if (str_contains($hay, $needle)) return ['type'=>'malware_http_indicator','risk'=>in_array($needle, ['alfa_data','alfacgiapi','?_bh_chk'])?'critical':'high'];
        if (str_contains($hay, 'loader.php') && str_contains($hay, 'whewr.php?delivery')) return ['type'=>'loader_after_delivery_referrer','risk'=>'high'];
        if (($p['method'] ?? '') === 'POST' && preg_match('/\.php(\?|$)/i', (string)$p['uri']) && !preg_match('/(wp-admin|administrator|admin|index\.php)/i', (string)$p['uri'])) return ['type'=>'post_unknown_php','risk'=>'medium'];
        if (str_contains($hay, 'mrz')) return ['type'=>'suspicious_mrz','risk'=>'medium'];
        return null;
    }
}
