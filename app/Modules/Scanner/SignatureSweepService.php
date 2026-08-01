<?php
namespace App\Modules\Scanner;

use App\Support\DB;
use RuntimeException;

/**
 * Checks every already-inventoried site's webroot against exactly one signature - skipping
 * the full per-file analysis pipeline (no other signatures, no heuristic rules, no log
 * correlation) - so "we just found a new shell, check the whole server for this exact one
 * right now" is fast instead of waiting for or running a full scan of every site.
 */
class SignatureSweepService
{
    public function __construct(private ?SignatureEngine $engine = null, private ?ScannerService $scanner = null)
    {
        $this->engine ??= new SignatureEngine();
        $this->scanner ??= new ScannerService();
    }

    /** @return array{signature:array,sites_scanned:int,files_scanned:int,finding_ids:int[]} */
    public function sweep(int $signatureId): array
    {
        $sig = DB::first('SELECT * FROM malware_signatures WHERE id=?', [$signatureId]);
        if (!$sig) throw new RuntimeException('Signature not found.');
        $type = $sig['pattern_type'] ?? 'substring';
        $needsContent = $type !== 'hash';
        $needsShaUpfront = $type === 'hash';
        $extensions = array_map('strtolower', (array) (json_decode((string) $sig['target_extensions'], true) ?: []));

        $filesScanned = 0; $findingIds = []; $sitesScanned = 0;
        foreach (DB::select('SELECT id, name, path FROM sites') as $site) {
            if (!is_dir($site['path'])) continue;
            $sitesScanned++;
            foreach ($this->scanner->directoryIterator($site['path']) as $file) {
                if (!$file->isFile() || $file->isLink()) continue;
                $path = $file->getPathname();
                $ext = strtolower($file->getExtension());
                if ($extensions && !in_array($ext, $extensions, true)) continue;
                $filesScanned++;
                $content = $needsContent ? ((string) @file_get_contents($path, false, null, 0, config('guard.max_file_read_bytes'))) : '';
                $sha256 = $needsShaUpfront ? (@hash_file('sha256', $path) ?: null) : null;
                $relative = ltrim(str_replace($site['path'], '', $path), '/');
                $match = $this->engine->match($sig, $path, $relative, ['extension' => $ext, 'sha256' => $sha256], $content, $site['path']);
                if (!$match) continue;
                if ($sha256 === null) $sha256 = @hash_file('sha256', $path) ?: null;
                $findingId = $this->recordFinding((int) $site['id'], $path, $sha256, $sig, $match);
                if ($findingId !== null) $findingIds[] = $findingId;
            }
        }
        return ['signature' => $sig, 'sites_scanned' => $sitesScanned, 'files_scanned' => $filesScanned, 'finding_ids' => $findingIds];
    }

    /**
     * Mirrors ScannerService::upsertFinding()'s fingerprint/finding_hash derivation and
     * ignored-finding check so a sweep match for the same file+signature dedupes with (and
     * doesn't resurrect an ignored copy of) a finding a normal scan would have produced.
     */
    private function recordFinding(int $siteId, string $path, ?string $sha256, array $sig, array $match): ?int
    {
        $stat = @stat($path) ?: [];
        $size = $stat['size'] ?? 0;
        $mtime = isset($stat['mtime']) ? gmdate('Y-m-d H:i:s', $stat['mtime']) : null;
        $owner = function_exists('posix_getpwuid') ? (posix_getpwuid($stat['uid'] ?? 0)['name'] ?? (string) ($stat['uid'] ?? '')) : (string) ($stat['uid'] ?? '');
        $permissions = substr(sprintf('%o', @fileperms($path)), -4);
        $pathHash = hash('sha256', $path);
        $type = $sig['type'] ?? 'signature';
        $ruleKey = 'signature:' . ($sig['slug'] ?? $sig['name']);
        $fingerprint = hash('sha256', $path . '|' . $type . '|' . $ruleKey . '|' . ($sha256 ?? ''));
        $findingHash = hash('sha256', $path . '|' . $type . '|' . $ruleKey . '|' . $fingerprint);
        $matchDetails = json_encode(['signature' => $sig['name'], 'signature_id' => $sig['id'], 'source' => $sig['source'] ?? 'sweep', 'matched' => $match['matched'] ?? []], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $ignored = DB::first("SELECT id,sha256 FROM findings WHERE finding_hash=? AND path_hash=? AND path=? AND status='ignored'", [$findingHash, $pathHash, $path]);
        if ($ignored && ($ignored['sha256'] ?? null) === $sha256) return null;
        $row = DB::first("SELECT id,status FROM findings WHERE finding_hash=? AND path_hash=? AND path=? AND status NOT IN ('ignored','quarantined')", [$findingHash, $pathHash, $path]);
        if ($row) {
            DB::statement('UPDATE findings SET rule_key=?,finding_hash=?,risk=?,title=?,description=?,sha256=?,size=?,mtime=?,owner=?,permissions=?,last_seen_at=?,last_matched_signature_id=?,matched_signature_name=?,matched_signature_source=?,signature_match_details=?,updated_at=? WHERE id=?', [
                $ruleKey, $findingHash, $sig['risk'] ?? 'critical', 'Signature sweep match: ' . $sig['name'], $sig['description'] ?? '', $sha256, $size, $mtime, $owner, $permissions, now(), $sig['id'], $sig['name'], $sig['source'] ?? 'sweep', $matchDetails, now(), $row['id'],
            ]);
            return (int) $row['id'];
        }
        return (int) DB::insert('INSERT INTO findings (scan_run_id,first_seen_scan_id,last_seen_scan_id,last_matched_signature_id,matched_signature_name,matched_signature_source,signature_match_details,site_id,path,path_hash,finding_hash,risk,status,type,rule_key,fingerprint,title,description,matched_rules,related_log_event_ids,sha256,size,mtime,owner,permissions,first_seen_at,last_seen_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [
            null, null, null, $sig['id'], $sig['name'], $sig['source'] ?? 'sweep', $matchDetails, $siteId, $path, $pathHash, $findingHash, $sig['risk'] ?? 'critical', 'new', $type, $ruleKey, $fingerprint, 'Signature sweep match: ' . $sig['name'], $sig['description'] ?? '', '[]', '[]', $sha256, $size, $mtime, $owner, $permissions, now(), now(), now(), now(),
        ]);
    }
}
