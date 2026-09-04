<?php
namespace App\Modules\Reports;

use App\Support\DB;
use RuntimeException;

class ScanReportService
{
    private const COMPLETED = "('completed','completed_with_limit')";

    public function latestCompletedRunForUser(int $userId): ?array
    {
        $user = DB::first('SELECT * FROM users WHERE id=?', [$userId]);
        if (!$user) return null;
        return DB::first(
            "SELECT r.* FROM scan_runs r
             WHERE r.status IN " . self::COMPLETED . " AND (
                (r.scope_type='user' AND r.scope_value=?) OR
                (r.scope_type='full' AND COALESCE(r.finished_at,r.started_at) >= COALESCE(?,r.started_at))
             )
             ORDER BY COALESCE(r.finished_at,r.started_at) DESC,r.id DESC LIMIT 1",
            [$user['name'], $user['created_at'] ?? null]
        );
    }

    public function latestRunIdsByUser(array $users): array
    {
        $result = [];
        foreach ($users as $user) {
            $run = $this->latestCompletedRunForUser((int)$user['id']);
            $result[(int)$user['id']] = $run ? (int)$run['id'] : null;
        }
        return $result;
    }

    public function forUser(int $userId): array
    {
        $user = DB::first('SELECT * FROM users WHERE id=?', [$userId]);
        if (!$user) throw new RuntimeException('User not found.');
        $run = $this->latestCompletedRunForUser($userId);
        if (!$run) throw new RuntimeException('No completed scan containing this user was found.');
        return $this->build($run, $user, null, 'user');
    }

    public function forRun(int $runId): array
    {
        $run = DB::first('SELECT * FROM scan_runs WHERE id=? AND status IN '.self::COMPLETED, [$runId]);
        if (!$run) throw new RuntimeException('Completed scan run not found.');

        $user = null;
        $site = null;
        if (($run['scope_type'] ?? '') === 'user' && ($run['scope_value'] ?? '') !== '') {
            $user = DB::first('SELECT * FROM users WHERE name=?', [$run['scope_value']]);
        } elseif (($run['scope_type'] ?? '') === 'site' && ($run['scope_value'] ?? '') !== '') {
            $site = DB::first('SELECT * FROM sites WHERE path=? OR name=? ORDER BY CASE WHEN path=? THEN 0 ELSE 1 END LIMIT 1', [$run['scope_value'],$run['scope_value'],$run['scope_value']]);
        }
        return $this->build($run, $user, $site, (string)($run['scope_type'] ?? 'full'));
    }

    private function build(array $run, ?array $user, ?array $site, string $requestedScope): array
    {
        [$siteWhere,$siteParams,$findingWhere,$findingParams] = $this->scopeSql($user, $site);
        $runId = (int)$run['id'];

        $siteCoverage = ($user || $site)
            ? '1=1'
            : '(EXISTS (SELECT 1 FROM file_snapshots fs WHERE fs.site_id=s.id AND fs.last_seen_scan_id=?) OR EXISTS (SELECT 1 FROM scan_run_findings srfx INNER JOIN findings fx ON fx.id=srfx.finding_id WHERE fx.site_id=s.id AND srfx.scan_run_id=?))';
        $coverageParams = ($user || $site) ? [] : [$runId,$runId];
        $sites = DB::select(
            "SELECT s.id,s.name,s.path,s.type,s.cms_type,s.cms_version,s.cms_detected_at,s.cms_confidence,s.cms_admin_path,s.is_active,s.last_scan_at,u.name user_name
             FROM sites s LEFT JOIN users u ON u.id=s.server_user_id
             WHERE {$siteCoverage}{$siteWhere}
             ORDER BY u.name,s.name,s.path",
            array_merge($coverageParams, $siteParams)
        );

        $rows = DB::select(
            "SELECT f.*,srf.observed_at observed_at_in_scan,s.name site_name,s.path site_path,u.name user_name,
                    fs.is_missing current_file_missing,fs.last_seen_at current_file_last_seen_at,
                    fs.last_changed_at current_file_last_changed_at,fs.baseline_status current_baseline_status
             FROM findings f
             INNER JOIN scan_run_findings srf ON srf.finding_id=f.id
             LEFT JOIN sites s ON s.id=f.site_id
             LEFT JOIN users u ON u.id=s.server_user_id
             LEFT JOIN file_snapshots fs ON fs.site_id=f.site_id AND fs.path_hash=f.path_hash
             WHERE srf.scan_run_id=?{$findingWhere}
             ORDER BY CASE f.risk WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,u.name,s.name,f.path,f.id",
            array_merge([$runId], $findingParams)
        );

        $findingIds = array_values(array_unique(array_map(fn($row)=>(int)$row['id'], $rows)));
        $logIds = [];
        $signatureIds = [];
        foreach ($rows as $row) {
            foreach ($this->decodeList($row['related_log_event_ids'] ?? null) as $id) if ((int)$id > 0) $logIds[] = (int)$id;
            if ((int)($row['last_matched_signature_id'] ?? 0) > 0) $signatureIds[] = (int)$row['last_matched_signature_id'];
        }

        $logsById = [];
        foreach ($this->selectByIds('log_events', array_values(array_unique($logIds))) as $log) {
            $logsById[(int)$log['id']] = $this->logForReport($log);
        }
        $quarantineByFinding = [];
        foreach ($this->selectByIds('quarantine_items', $findingIds, 'finding_id') as $item) {
            $quarantineByFinding[(int)$item['finding_id']][] = $this->only($item, ['id','original_path','quarantine_path','sha256','owner','group','permissions','mtime','reason','status','created_at','updated_at']);
        }
        $analysesByFinding = [];
        foreach ($this->selectByIds('ai_analyses', $findingIds, 'finding_id') as $analysis) {
            $analysesByFinding[(int)$analysis['finding_id']][] = $this->only($analysis, ['id','provider','model','risk','confidence','summary','created_at','updated_at']);
        }

        $findings = [];
        foreach ($rows as $row) {
            $relatedLogIds = [];
            foreach ($this->decodeList($row['related_log_event_ids'] ?? null) as $id) if (isset($logsById[(int)$id])) $relatedLogIds[] = (int)$id;
            $id = (int)$row['id'];
            $findings[] = [
                'id'=>$id,
                'new_in_this_scan'=>(int)($row['first_seen_scan_id'] ?? 0) === $runId,
                'observed_at_in_scan'=>$row['observed_at_in_scan'],
                'risk'=>$row['risk'], 'status'=>$row['status'], 'type'=>$row['type'],
                'rule_key'=>$row['rule_key'], 'fingerprint'=>$row['fingerprint'],
                'user'=>$row['user_name'], 'site'=>$row['site_name'], 'site_path'=>$row['site_path'],
                'path'=>$row['path'], 'sha256'=>$row['sha256'],
                'size'=>$row['size'] !== null ? (int)$row['size'] : null,
                'mtime'=>$row['mtime'], 'owner'=>$row['owner'], 'permissions'=>$row['permissions'],
                'title'=>$row['title'], 'description'=>$row['description'],
                'matched_rules'=>$this->decodeList($row['matched_rules'] ?? null),
                'matched_signature'=>[
                    'id'=>(int)($row['last_matched_signature_id'] ?? 0) ?: null,
                    'name'=>$row['matched_signature_name'],
                    'source'=>$row['matched_signature_source'],
                    'details'=>$this->decodeValue($row['signature_match_details'] ?? null),
                ],
                'file_state'=>[
                    'missing'=>(bool)($row['current_file_missing'] ?? false),
                    'last_seen_at'=>$row['current_file_last_seen_at'],
                    'last_changed_at'=>$row['current_file_last_changed_at'],
                    'baseline_status'=>$row['current_baseline_status'],
                ],
                'first_seen_at'=>$row['first_seen_at'], 'last_seen_at'=>$row['last_seen_at'],
                'first_seen_scan_id'=>(int)($row['first_seen_scan_id'] ?? 0) ?: null,
                'last_seen_scan_id'=>(int)($row['last_seen_scan_id'] ?? 0) ?: null,
                'related_log_event_ids'=>$relatedLogIds,
                'quarantine_history'=>$quarantineByFinding[$id] ?? [],
                'ai_analyses'=>$analysesByFinding[$id] ?? [],
            ];
        }

        $signatures = [];
        foreach ($this->selectByIds('malware_signatures', array_values(array_unique($signatureIds))) as $signature) {
            $signatures[] = [
                'id'=>(int)$signature['id'], 'name'=>$signature['name'], 'slug'=>$signature['slug'],
                'description'=>$signature['description'], 'risk'=>$signature['risk'], 'type'=>$signature['type'],
                'pattern_type'=>$signature['pattern_type'], 'pattern'=>$this->decodeValue($signature['pattern_json']),
                'target_extensions'=>$this->decodeList($signature['target_extensions'] ?? null),
                'target_paths'=>$this->decodeList($signature['target_paths'] ?? null),
                'exclude_paths'=>$this->decodeList($signature['exclude_paths'] ?? null),
                'required_hits'=>$signature['required_hits'] !== null ? (int)$signature['required_hits'] : null,
                'enabled'=>(bool)$signature['enabled'], 'source'=>$signature['source'],
                'source_finding_id'=>(int)($signature['source_finding_id'] ?? 0) ?: null,
                'source_file_sha256'=>$signature['source_file_sha256'], 'confidence'=>$signature['confidence'],
                'false_positive_notes'=>$signature['false_positive_notes'],
            ];
        }

        return [
            'format'=>'jura-server-guard-scan-report',
            'format_version'=>'1.0',
            'generated_at'=>gmdate('c'),
            'generator'=>'Jura Server Guard',
            'host'=>['hostname'=>@gethostname() ?: null],
            'report_scope'=>[
                'type'=>$requestedScope,
                'user'=>$user ? $this->only($user, ['id','name','base_path']) : null,
                'site'=>$site ? $this->only($site, ['id','name','path','type','cms_type','cms_version']) : null,
            ],
            'scan'=>$this->scanForReport($run),
            'summary'=>[
                'sites'=>count($sites),
                'findings'=>count($findings),
                'new_findings'=>count(array_filter($findings, fn($finding)=>$finding['new_in_this_scan'])),
                'by_risk'=>$this->counts($findings, 'risk'),
                'by_status'=>$this->counts($findings, 'status'),
                'by_type'=>$this->counts($findings, 'type'),
            ],
            'sites'=>$sites,
            'signatures'=>$signatures,
            'related_log_events'=>array_values($logsById),
            'findings'=>$findings,
            'analysis_notes'=>[
                'Findings are scanner observations, not a final malware verdict; review matched evidence and file context.',
                'Absolute paths are intentionally included. File contents, environment values, credentials, and raw log lines are not included.',
                'Sensitive query-string values in related log URIs and referrers are redacted.',
                ($run['status'] ?? '') === 'completed_with_limit' ? 'This scan stopped at a configured time/file limit and may be incomplete.' : 'This scan completed without a configured limit being reported as reached.',
            ],
        ];
    }

    private function scopeSql(?array $user, ?array $site): array
    {
        if ($user) return [' AND s.server_user_id=?', [(int)$user['id']], ' AND u.id=?', [(int)$user['id']]];
        if ($site) return [' AND s.id=?', [(int)$site['id']], ' AND s.id=?', [(int)$site['id']]];
        return ['', [], '', []];
    }

    private function scanForReport(array $run): array
    {
        $fields = ['id','started_at','finished_at','status','scope_type','scope_value','profile','scan_mode','previous_scan_id','files_scanned','total_files_estimated','files_seen_total','files_new','files_modified','files_deleted','files_changed_total','files_analyzed','files_skipped_unchanged','skipped_media','skipped_directories','findings_count','findings_new','error_text'];
        $scan = $this->only($run, $fields);
        foreach (['id','previous_scan_id','files_scanned','total_files_estimated','files_seen_total','files_new','files_modified','files_deleted','files_changed_total','files_analyzed','files_skipped_unchanged','skipped_media','skipped_directories','findings_count','findings_new'] as $field) {
            if (array_key_exists($field,$scan) && $scan[$field] !== null) $scan[$field] = (int)$scan[$field];
        }
        $scan['diff_summary'] = $this->decodeValue($run['diff_summary'] ?? null);
        return $scan;
    }

    private function selectByIds(string $table, array $ids, string $column = 'id'): array
    {
        $allowed = ['log_events'=>['id'],'quarantine_items'=>['finding_id'],'ai_analyses'=>['finding_id'],'malware_signatures'=>['id']];
        if (!isset($allowed[$table]) || !in_array($column,$allowed[$table],true)) return [];
        $rows = [];
        foreach (array_chunk(array_values(array_unique(array_filter(array_map('intval',$ids)))), 500) as $chunk) {
            if (!$chunk) continue;
            $placeholders = implode(',', array_fill(0,count($chunk),'?'));
            $rows = array_merge($rows, DB::select("SELECT * FROM {$table} WHERE {$column} IN ({$placeholders}) ORDER BY id", $chunk));
        }
        return $rows;
    }

    private function logForReport(array $log): array
    {
        return [
            'id'=>(int)$log['id'], 'log_path'=>$log['log_path'], 'line_number'=>$log['line_number'] !== null ? (int)$log['line_number'] : null,
            'ip'=>$log['ip'], 'method'=>$log['method'], 'uri'=>$this->redactUri($log['uri']),
            'status_code'=>$log['status_code'] !== null ? (int)$log['status_code'] : null,
            'event_type'=>$log['event_type'], 'risk'=>$log['risk'], 'user_agent'=>$log['user_agent'],
            'referer'=>$this->redactUri($log['referer']),
            'created_at'=>$log['created_at'],
        ];
    }

    private function redactUri(?string $value): ?string
    {
        if ($value === null || $value === '') return $value;
        return preg_replace('/([?&](?:access[_-]?token|api[_-]?key|key|token|password|passwd|pass|secret|authorization|auth|session|sessionid|code)=)[^&#]*/i', '$1[REDACTED]', $value) ?? $value;
    }

    private function decodeList(mixed $value): array
    {
        $decoded = $this->decodeValue($value);
        return is_array($decoded) ? $decoded : [];
    }

    private function decodeValue(mixed $value): mixed
    {
        if (!is_string($value) || trim($value) === '') return null;
        $decoded = json_decode($value, true);
        return json_last_error() === JSON_ERROR_NONE ? $decoded : $value;
    }

    private function counts(array $rows, string $field): array
    {
        $counts = [];
        foreach ($rows as $row) {
            $key = (string)($row[$field] ?? 'unknown');
            $counts[$key] = ($counts[$key] ?? 0) + 1;
        }
        arsort($counts);
        return $counts;
    }

    private function only(array $row, array $fields): array
    {
        $result = [];
        foreach ($fields as $field) $result[$field] = $row[$field] ?? null;
        return $result;
    }
}
