<?php
namespace App\Modules\Incidents;

use App\Support\DB;
use Throwable;

class IncidentImportService
{
    public function validate(array $data): array
    {
        $errors = [];
        if (($data['format'] ?? '') !== 'jura-server-guard-incident') $errors[] = 'format must be "jura-server-guard-incident"';
        if (!str_starts_with((string)($data['format_version'] ?? ''), '1.')) $errors[] = 'format_version must start with "1."';
        $incident = (array)($data['incident'] ?? []);
        if (empty($incident['id'])) $errors[] = 'incident.id is required';
        if (empty($incident['title'])) $errors[] = 'incident.title is required';
        if (!in_array($incident['severity'] ?? '', ['low', 'medium', 'high', 'critical'], true)) $errors[] = 'incident.severity must be one of low|medium|high|critical';
        foreach ((array)($data['threat_ips'] ?? []) as $i => $ip) {
            if (empty($ip['ip'])) $errors[] = "threat_ips[$i].ip is required";
            if (!in_array($ip['classification'] ?? '', ['scanner', 'bruteforce', 'webshell_access', 'bot', 'direct_login', 'manual', 'unknown'], true)) $errors[] = "threat_ips[$i].classification is invalid";
            if (!in_array($ip['risk'] ?? '', ['low', 'medium', 'high', 'critical'], true)) $errors[] = "threat_ips[$i].risk is invalid";
        }
        foreach ((array)($data['malware_signatures'] ?? []) as $i => $sig) {
            if (empty($sig['slug'])) $errors[] = "malware_signatures[$i].slug is required";
            if (empty($sig['name'])) $errors[] = "malware_signatures[$i].name is required";
            if (!in_array($sig['risk'] ?? '', ['low', 'medium', 'high', 'critical'], true)) $errors[] = "malware_signatures[$i].risk is invalid";
            if (empty($sig['type']) || !is_string($sig['type'])) $errors[] = "malware_signatures[$i].type is required";
            if (!in_array($sig['pattern_type'] ?? '', ['hash', 'combo', 'regex', 'substring', 'structural'], true)) $errors[] = "malware_signatures[$i].pattern_type is invalid";
            if (!is_array($sig['pattern_json'] ?? null)) $errors[] = "malware_signatures[$i].pattern_json must be an object";
        }
        foreach ((array)($data['file_iocs'] ?? []) as $i => $ioc) {
            if (empty($ioc['sha256']) || !preg_match('/^[a-f0-9]{64}$/i', (string)$ioc['sha256'])) $errors[] = "file_iocs[$i].sha256 must be a 64-char hex SHA-256";
        }
        return $errors;
    }

    /** @return array{ok:bool,errors?:array,dry_run?:bool,summary?:array} */
    public function import(array $data, bool $dryRun = false, ?string $sourceFile = null): array
    {
        $errors = $this->validate($data);
        if ($errors) return ['ok' => false, 'errors' => $errors];

        $extId = (string) $data['incident']['id'];
        $summary = [
            'incident_external_id' => $extId,
            'incident_action' => DB::first('SELECT id FROM incidents WHERE external_id=?', [$extId]) ? 'update' : 'create',
            'threat_ips' => ['created' => 0, 'updated' => 0],
            'signatures' => ['created' => 0, 'updated' => 0],
            'file_iocs' => ['created' => 0, 'updated' => 0],
            'excluded_ips_recorded' => count((array) ($data['excluded_ips'] ?? [])),
        ];

        if ($dryRun) {
            foreach ((array) ($data['threat_ips'] ?? []) as $ip) {
                DB::first('SELECT id FROM threat_ips WHERE ip=?', [$ip['ip']]) ? $summary['threat_ips']['updated']++ : $summary['threat_ips']['created']++;
            }
            foreach ((array) ($data['malware_signatures'] ?? []) as $sig) {
                DB::first('SELECT id FROM malware_signatures WHERE slug=?', [$sig['slug']]) ? $summary['signatures']['updated']++ : $summary['signatures']['created']++;
            }
            foreach ((array) ($data['file_iocs'] ?? []) as $ioc) {
                DB::first('SELECT id FROM incident_file_iocs WHERE sha256=?', [strtolower($ioc['sha256'])]) ? $summary['file_iocs']['updated']++ : $summary['file_iocs']['created']++;
            }
            return ['ok' => true, 'dry_run' => true, 'summary' => $summary];
        }

        $pdo = DB::pdo();
        $pdo->beginTransaction();
        try {
            $incidentId = $this->upsertIncident($data, $sourceFile);
            $source = 'incident:' . $extId;

            foreach ((array) ($data['threat_ips'] ?? []) as $ip) {
                [$created, $threatIpId] = $this->upsertThreatIp($ip, $incidentId, $source);
                $summary['threat_ips'][$created ? 'created' : 'updated']++;
                $this->linkIncident('incident_threat_ip_links', 'threat_ip_id', $incidentId, $threatIpId);
            }
            foreach ((array) ($data['malware_signatures'] ?? []) as $sig) {
                [$created, $signatureId] = $this->upsertSignature($sig, $incidentId);
                $summary['signatures'][$created ? 'created' : 'updated']++;
                $this->linkIncident('incident_signature_links', 'signature_id', $incidentId, $signatureId);
            }
            foreach ((array) ($data['file_iocs'] ?? []) as $ioc) {
                [$created, $fileIocId] = $this->upsertFileIoc($ioc, $incidentId);
                $summary['file_iocs'][$created ? 'created' : 'updated']++;
                $this->linkIncident('incident_file_ioc_links', 'file_ioc_id', $incidentId, $fileIocId);
            }
            $pdo->commit();
        } catch (Throwable $e) {
            $pdo->rollBack();
            return ['ok' => false, 'errors' => ['Import failed and was rolled back: ' . $e->getMessage()]];
        }
        $summary['incident_id'] = $incidentId;
        return ['ok' => true, 'dry_run' => false, 'summary' => $summary];
    }

    private function linkIncident(string $table, string $foreignKeyColumn, int $incidentId, int $foreignId): void
    {
        if (DB::first("SELECT id FROM $table WHERE incident_id=? AND $foreignKeyColumn=?", [$incidentId, $foreignId])) return;
        DB::insert("INSERT INTO $table (incident_id, $foreignKeyColumn, created_at) VALUES (?,?,?)", [$incidentId, $foreignId, now()]);
    }

    private function upsertIncident(array $data, ?string $sourceFile): int
    {
        $incident = $data['incident'];
        $extId = (string) $incident['id'];
        $existing = DB::first('SELECT id FROM incidents WHERE external_id=?', [$extId]);
        $fields = [
            $incident['title'],
            $incident['severity'] ?? 'medium',
            $incident['confidence'] ?? null,
            $incident['status'] ?? null,
            $incident['summary'] ?? null,
            $incident['server']['hostname'] ?? null,
            json_encode($incident['timeline'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            json_encode($data['affected_assets'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            json_encode($data['path_indicators'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            json_encode($data['excluded_ips'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            json_encode($data['response_actions'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            json_encode($data['import_policy'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            $sourceFile,
            now(),
        ];
        if ($existing) {
            DB::statement('UPDATE incidents SET title=?,severity=?,confidence=?,status=?,summary=?,server_hostname=?,timeline_json=?,affected_assets_json=?,path_indicators_json=?,excluded_ips_json=?,response_actions_json=?,import_policy_json=?,raw_json=?,source_file=?,imported_at=?,updated_at=? WHERE id=?', [...$fields, now(), $existing['id']]);
            return (int) $existing['id'];
        }
        return DB::insert('INSERT INTO incidents (external_id,title,severity,confidence,status,summary,server_hostname,timeline_json,affected_assets_json,path_indicators_json,excluded_ips_json,response_actions_json,import_policy_json,raw_json,source_file,imported_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [$extId, ...$fields, now(), now()]);
    }

    /** @return array{0:bool,1:int} [created, threat_ip_id] */
    private function upsertThreatIp(array $ip, int $incidentId, string $source): array
    {
        $existing = DB::first('SELECT id, hit_count FROM threat_ips WHERE ip=?', [$ip['ip']]);
        $hitCount = isset($ip['hit_count']) ? (int) $ip['hit_count'] : (int) ($existing['hit_count'] ?? 0);
        $fields = [$ip['classification'], $ip['risk'], $ip['confidence'] ?? null, $ip['notes'] ?? null, $hitCount, $ip['recommended_action'] ?? null, $incidentId, $source];
        if ($existing) {
            DB::statement('UPDATE threat_ips SET classification=?,risk=?,confidence=?,notes=?,hit_count=?,recommended_action=?,incident_id=?,source=?,last_seen_at=?,updated_at=? WHERE id=?', [...$fields, now(), now(), $existing['id']]);
            return [false, (int) $existing['id']];
        }
        return [true, DB::insert('INSERT INTO threat_ips (ip,classification,risk,confidence,notes,hit_count,recommended_action,incident_id,source,first_seen_at,last_seen_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', [$ip['ip'], ...$fields, now(), now(), now(), now()])];
    }

    /** @return array{0:bool,1:int} [created, signature_id] */
    private function upsertSignature(array $sig, int $incidentId): array
    {
        $existing = DB::first('SELECT id FROM malware_signatures WHERE slug=?', [$sig['slug']]);
        $fields = [
            $sig['name'],
            $sig['description'] ?? null,
            $sig['risk'],
            $sig['type'],
            $sig['pattern_type'],
            json_encode($sig['pattern_json'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            json_encode($sig['target_extensions'] ?? [], JSON_UNESCAPED_SLASHES),
            json_encode($sig['target_paths'] ?? [], JSON_UNESCAPED_SLASHES),
            json_encode($sig['exclude_paths'] ?? [], JSON_UNESCAPED_SLASHES),
            (int) ($sig['required_hits'] ?? 1),
            !empty($sig['enabled']) ? 1 : 0,
            $incidentId,
        ];
        if ($existing) {
            DB::statement('UPDATE malware_signatures SET name=?,description=?,risk=?,type=?,pattern_type=?,pattern_json=?,target_extensions=?,target_paths=?,exclude_paths=?,required_hits=?,enabled=?,incident_id=?,source=?,updated_at=? WHERE id=?', [...$fields, 'incident', now(), $existing['id']]);
            return [false, (int) $existing['id']];
        }
        return [true, DB::insert('INSERT INTO malware_signatures (name,slug,description,risk,type,pattern_type,pattern_json,target_extensions,target_paths,exclude_paths,required_hits,enabled,incident_id,source,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [$fields[0], $sig['slug'], $fields[1], $fields[2], $fields[3], $fields[4], $fields[5], $fields[6], $fields[7], $fields[8], $fields[9], $fields[10], $fields[11], 'incident', now(), now()])];
    }

    /** @return array{0:bool,1:int} [created, file_ioc_id] */
    private function upsertFileIoc(array $ioc, int $incidentId): array
    {
        $sha = strtolower($ioc['sha256']);
        $existing = DB::first('SELECT id FROM incident_file_iocs WHERE sha256=?', [$sha]);
        $fields = [$incidentId, isset($ioc['size']) ? (int) $ioc['size'] : null, json_encode($ioc['names'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), $ioc['role'] ?? null, $ioc['risk'] ?? null, $ioc['confidence'] ?? null, $ioc['scope'] ?? null];
        if ($existing) {
            DB::statement('UPDATE incident_file_iocs SET incident_id=?,size=?,names_json=?,role=?,risk=?,confidence=?,scope=?,updated_at=? WHERE id=?', [...$fields, now(), $existing['id']]);
            return [false, (int) $existing['id']];
        }
        return [true, DB::insert('INSERT INTO incident_file_iocs (incident_id,size,names_json,role,risk,confidence,scope,sha256,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)', [...$fields, $sha, now(), now()])];
    }
}
