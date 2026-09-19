<?php
namespace App\Modules\Feed;

use App\Support\DB;
use PharData;
use Phar;
use Throwable;

/**
 * Push side of the signatures feed (the pull side is FeedService). After every locally-authored,
 * non-dry-run `guard:incident-import`, prepareFromIncident() stages an ANONYMIZED contribution in
 * feed_outbox automatically -- but never publishes it. Publishing (creating a GitHub Release in
 * the feed repo, which every other installation can then pull) is always an explicit, separate
 * step via publish(), mirroring the existing pull-side rule that nothing crosses a trust boundary
 * without a human decision: there, a feed-sourced signature never goes live without approval;
 * here, a locally-sourced contribution never leaves the server without approval.
 *
 * Anonymization is deliberately narrow and structural, not a best-effort text scrub: only fields
 * that cannot contain a site name, path, or narrative are carried over (risk/type/pattern_type/
 * pattern_json/target_extensions from signatures; sha256/size/names/role/risk/confidence from file
 * IOCs; pattern/kind/risk/confidence from path indicators). Signature name/slug/description are
 * NEVER copied -- in every real incident file reviewed while building this, they embedded the
 * site's own short account name (e.g. "JuraLand wp-yahho.php webshell exact hash", slug
 * "juraland-20260830-wp-yahho-sha256") -- so they are always regenerated from the structural data
 * alone. Everything else (incident.server, title, summary, response_actions, data_gaps,
 * threat_ips, and file_iocs'/path_indicators' own path/scope/notes fields) is dropped entirely
 * rather than filtered, since free text is exactly where a site name leaks and cannot be stripped
 * reliably by pattern matching.
 */
class FeedContributionService
{
    public function repo(): string
    {
        return trim((string) config('guard.feed_publish_repo', config('guard.feed_repo')), '/');
    }

    public function outboxDir(): string
    {
        return storage_path('feed-outbox');
    }

    /** Drafts and published contributions, newest first. */
    public function listOutbox(): array
    {
        return DB::select('SELECT * FROM feed_outbox ORDER BY id DESC');
    }

    /**
     * Builds and stages an anonymized contribution from an already-imported incident. Idempotent
     * per source incident: refreshes the existing draft in place on re-import (same anon id), and
     * deliberately does nothing if that incident's contribution was already published -- a
     * published contribution is a fact about what was shared, not something to silently rewrite.
     *
     * @return array{ok:bool,outbox_id?:int,skipped?:string,error?:string}
     */
    public function prepareFromIncident(int $incidentId): array
    {
        try {
            $incident = DB::first('SELECT * FROM incidents WHERE id=?', [$incidentId]);
            if (!$incident) return ['ok' => false, 'error' => 'Incident not found.'];

            $existing = DB::first('SELECT id, anon_incident_id, status FROM feed_outbox WHERE source_incident_id=?', [$incidentId]);
            if ($existing && $existing['status'] === 'published') {
                return ['ok' => true, 'skipped' => 'already_published', 'outbox_id' => (int) $existing['id']];
            }
            $anonId = $existing['anon_incident_id'] ?? ('anon-' . bin2hex(random_bytes(8)));

            $signatures = DB::select('SELECT ms.* FROM malware_signatures ms JOIN incident_signature_links l ON l.signature_id=ms.id WHERE l.incident_id=? ORDER BY ms.id', [$incidentId]);
            $fileIocs = DB::select('SELECT f.* FROM incident_file_iocs f JOIN incident_file_ioc_links l ON l.file_ioc_id=f.id WHERE l.incident_id=? ORDER BY f.id', [$incidentId]);
            $pathIndicators = json_decode((string) ($incident['path_indicators_json'] ?? '[]'), true) ?: [];

            $anonSignatures = [];
            foreach ($signatures as $sig) $anonSignatures[] = $this->anonymizeSignature($sig);
            $anonFileIocs = [];
            foreach ($fileIocs as $ioc) $anonFileIocs[] = $this->anonymizeFileIoc($ioc);
            $anonPathIndicators = [];
            foreach ($pathIndicators as $p) $anonPathIndicators[] = $this->anonymizePathIndicator($p);

            if (!$anonSignatures && !$anonFileIocs && !$anonPathIndicators) {
                return ['ok' => true, 'skipped' => 'nothing_shareable'];
            }

            $severity = in_array($incident['severity'] ?? '', ['low', 'medium', 'high', 'critical'], true) ? $incident['severity'] : 'medium';
            $title = sprintf('Anonymized community contribution: %d signature(s), %d file indicator(s)', count($anonSignatures), count($anonFileIocs));

            $doc = [
                'format' => 'jura-server-guard-incident',
                'format_version' => '1.0',
                'generated_at' => now(),
                'incident' => [
                    'id' => $anonId,
                    'title' => $title,
                    'severity' => $severity,
                    'confidence' => 'high',
                    'status' => 'contained_monitoring',
                    'summary' => 'Anonymized community-feed contribution generated automatically from a local incident report. Site/server identifiers, the original narrative summary, and response details are intentionally not included -- only structural detection data (signatures, file indicators, path indicators).',
                ],
                'threat_ips' => [],
                'excluded_ips' => [],
                'malware_signatures' => $anonSignatures,
                'file_iocs' => $anonFileIocs,
                'path_indicators' => $anonPathIndicators,
                'affected_assets' => ['confirmed_artifacts' => [], 'related_confirmed_activity' => [], 'operator_ip_observed_in_access_logs_not_equal_to_confirmed_compromise' => []],
                'response_actions' => [],
                'data_gaps' => [['field' => 'incident.server, incident.summary, response_actions, threat_ips, data_gaps', 'reason' => 'Omitted from this published community-feed contribution to avoid identifying the source site/server.']],
                'import_policy' => [
                    'threat_ip_upsert_key' => 'ip',
                    'signature_upsert_key' => 'slug',
                    'file_ioc_dedup_key' => 'sha256_when_available_else_name_size_markers',
                    'on_conflict' => 'update_mutable_fields_preserve_first_seen',
                    'dry_run_default' => true,
                    'notes' => 'Anonymized community-feed contribution; see docs/FEED.md.',
                ],
            ];

            $dir = $this->outboxDir();
            if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) return ['ok' => false, 'error' => "Could not create {$dir}."];
            $filePath = "{$dir}/{$anonId}.json";
            $json = json_encode($doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            file_put_contents($filePath, $json);
            chmod($filePath, 0600);
            $sha256 = hash('sha256', $json);

            if ($existing) {
                DB::statement('UPDATE feed_outbox SET title=?,severity=?,signature_count=?,file_ioc_count=?,file_path=?,sha256=?,updated_at=? WHERE id=?', [$title, $severity, count($anonSignatures), count($anonFileIocs), $filePath, $sha256, now(), $existing['id']]);
                return ['ok' => true, 'outbox_id' => (int) $existing['id']];
            }
            $outboxId = DB::insert('INSERT INTO feed_outbox (source_incident_id,anon_incident_id,title,severity,signature_count,file_ioc_count,status,file_path,sha256,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)', [$incidentId, $anonId, $title, $severity, count($anonSignatures), count($anonFileIocs), 'draft', $filePath, $sha256, now(), now()]);
            return ['ok' => true, 'outbox_id' => $outboxId];
        } catch (Throwable $e) {
            return ['ok' => false, 'error' => $e->getMessage()];
        }
    }

    private function anonymizeSignature(array $sig): array
    {
        $patternJson = json_decode((string) ($sig['pattern_json'] ?? '{}'), true) ?: [];
        $slug = 'sig-' . substr(hash('sha256', ($sig['pattern_type'] ?? '') . '|' . json_encode($patternJson, JSON_UNESCAPED_SLASHES)), 0, 24);
        return [
            'name' => sprintf('%s signature (%s, %s)', ucfirst((string) ($sig['type'] ?? 'malware')), $sig['pattern_type'] ?? 'unknown', $sig['risk'] ?? 'medium'),
            'slug' => $slug,
            'description' => 'Anonymized community-feed signature contribution.',
            'risk' => $sig['risk'] ?? 'medium',
            'type' => $sig['type'] ?? 'malware',
            'pattern_type' => $sig['pattern_type'] ?? 'substring',
            'pattern_json' => $patternJson,
            'target_extensions' => json_decode((string) ($sig['target_extensions'] ?? '[]'), true) ?: [],
            'target_paths' => [],
            'exclude_paths' => [],
            'required_hits' => 1,
            'enabled' => false,
            'source' => 'community-feed-contribution',
        ];
    }

    private function anonymizeFileIoc(array $ioc): array
    {
        return array_filter([
            'sha256' => $ioc['sha256'] ?? null,
            'size' => $ioc['size'] !== null ? (int) $ioc['size'] : null,
            'names' => json_decode((string) ($ioc['names_json'] ?? '[]'), true) ?: [],
            'role' => $ioc['role'] ?? null,
            'risk' => $ioc['risk'] ?? null,
            'confidence' => $ioc['confidence'] ?? null,
        ], fn($v) => $v !== null && $v !== []);
    }

    private function anonymizePathIndicator(array $p): array
    {
        return array_filter([
            'pattern' => $p['pattern'] ?? null,
            'kind' => $p['kind'] ?? null,
            'risk' => $p['risk'] ?? null,
            'confidence' => $p['confidence'] ?? null,
        ], fn($v) => $v !== null && $v !== '');
    }

    /**
     * Publishes one staged outbox draft: builds the same release-bundle shape FeedService already
     * knows how to consume (feed.json manifest + feed-bundle-<tag>.tar.gz + its .sha256 sidecar),
     * creates a new GitHub Release in the configured repo, and uploads both as release assets.
     * Requires guard.feed_publish_token (JURA_FEED_PUBLISH_TOKEN) with write access to that repo.
     *
     * @return array{ok:bool,error?:string,tag?:string,html_url?:string}
     */
    public function publish(int $outboxId): array
    {
        $row = DB::first('SELECT * FROM feed_outbox WHERE id=?', [$outboxId]);
        if (!$row) return ['ok' => false, 'error' => 'Outbox entry not found.'];
        if ($row['status'] === 'published') return ['ok' => false, 'error' => 'Already published as ' . $row['release_tag'] . '.'];

        $token = (string) config('guard.feed_publish_token');
        if ($token === '') return ['ok' => false, 'error' => 'guard.feed_publish_token (JURA_FEED_PUBLISH_TOKEN) is not configured.'];
        if (!is_file($row['file_path'])) return ['ok' => false, 'error' => "Staged file missing on disk: {$row['file_path']}."];
        if (hash_file('sha256', $row['file_path']) !== $row['sha256']) return ['ok' => false, 'error' => 'Staged file no longer matches its recorded checksum -- refusing to publish. Re-run guard:incident-import to refresh it.'];

        $tag = 'contrib-' . date('Ymd-His') . '-' . substr($row['anon_incident_id'], -8);
        $tmpDir = sys_get_temp_dir() . '/jura-feed-publish-' . bin2hex(random_bytes(6));
        if (!mkdir($tmpDir, 0700, true)) return ['ok' => false, 'error' => "Could not create temp dir {$tmpDir}."];

        try {
            $anonFile = "{$row['anon_incident_id']}.json";
            copy($row['file_path'], "{$tmpDir}/{$anonFile}");
            $manifest = ['feed_format' => 'jura-server-guard-feed', 'incidents' => [[
                'id' => $row['anon_incident_id'], 'file' => $anonFile, 'sha256' => $row['sha256'],
                'title' => $row['title'], 'severity' => $row['severity'],
                'signature_slugs' => array_column((array) (json_decode((string) file_get_contents($row['file_path']), true)['malware_signatures'] ?? []), 'slug'),
            ]]];
            file_put_contents("{$tmpDir}/feed.json", json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

            $bundleName = "feed-bundle-{$tag}.tar.gz";
            $tarPath = "{$tmpDir}/feed-bundle-{$tag}.tar";
            $phar = new PharData($tarPath);
            $phar->addFile("{$tmpDir}/feed.json", 'feed.json');
            $phar->addFile("{$tmpDir}/{$anonFile}", $anonFile);
            $phar->compress(Phar::GZ);
            unset($phar);
            @unlink($tarPath);
            $gzPath = "{$tarPath}.gz";
            if (!is_file($gzPath)) return ['ok' => false, 'error' => 'Failed to build the release bundle (.tar.gz compression failed).'];
            $bundleSha = hash_file('sha256', $gzPath);
            $checksumContent = "{$bundleSha}  {$bundleName}\n";

            $release = $this->githubPost("https://api.github.com/repos/{$this->repo()}/releases", $token, [
                'tag_name' => $tag,
                'name' => "Community contribution {$tag}",
                'body' => "Anonymized contribution: {$row['title']}\n\nGenerated and published automatically by Jura Server Guard's Feed page / guard:feed-publish. No site or server identifiers are included -- see docs/FEED.md in the panel's own repository for the anonymization rules.",
                'draft' => false,
                'prerelease' => false,
            ]);
            if (!$release['ok']) return $release;
            $uploadUrl = (string) preg_replace('/\{.*\}$/', '', (string) ($release['data']['upload_url'] ?? ''));
            if ($uploadUrl === '') return ['ok' => false, 'error' => 'GitHub release response had no upload_url.'];

            $up1 = $this->githubUploadAsset($uploadUrl, $token, $bundleName, 'application/gzip', (string) file_get_contents($gzPath));
            if (!$up1['ok']) return $up1;
            $up2 = $this->githubUploadAsset($uploadUrl, $token, "{$bundleName}.sha256", 'text/plain', $checksumContent);
            if (!$up2['ok']) return $up2;

            DB::statement("UPDATE feed_outbox SET status='published', release_tag=?, publish_error=NULL, published_at=?, updated_at=? WHERE id=?", [$tag, now(), now(), $outboxId]);
            return ['ok' => true, 'tag' => $tag, 'html_url' => (string) ($release['data']['html_url'] ?? '')];
        } catch (Throwable $e) {
            DB::statement('UPDATE feed_outbox SET publish_error=?, updated_at=? WHERE id=?', [$e->getMessage(), now(), $outboxId]);
            return ['ok' => false, 'error' => $e->getMessage()];
        } finally {
            foreach (glob("{$tmpDir}/*") ?: [] as $f) @unlink($f);
            @rmdir($tmpDir);
        }
    }

    /** @return array{ok:bool,data?:array,error?:string} */
    private function githubPost(string $url, string $token, array $body): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            CURLOPT_HTTPHEADER => ['User-Agent: jura-server-guard-feed-client', 'Accept: application/vnd.github+json', 'Authorization: token ' . $token, 'Content-Type: application/json'],
        ]);
        $responseBody = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($errno) return ['ok' => false, 'error' => "cURL error contacting GitHub: {$error}"];
        if ($httpCode < 200 || $httpCode >= 300) return ['ok' => false, 'error' => "GitHub API returned HTTP {$httpCode} creating the release: " . substr((string) $responseBody, 0, 500)];
        $decoded = json_decode((string) $responseBody, true);
        if (!is_array($decoded)) return ['ok' => false, 'error' => 'GitHub API returned unparsable JSON.'];
        return ['ok' => true, 'data' => $decoded];
    }

    /** @return array{ok:bool,error?:string} */
    private function githubUploadAsset(string $uploadUrl, string $token, string $filename, string $contentType, string $content): array
    {
        $ch = curl_init($uploadUrl . '?name=' . urlencode($filename));
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 60,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $content,
            CURLOPT_HTTPHEADER => ['User-Agent: jura-server-guard-feed-client', 'Accept: application/vnd.github+json', 'Authorization: token ' . $token, 'Content-Type: ' . $contentType, 'Content-Length: ' . strlen($content)],
        ]);
        $responseBody = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($errno) return ['ok' => false, 'error' => "cURL error uploading {$filename}: {$error}"];
        if ($httpCode < 200 || $httpCode >= 300) return ['ok' => false, 'error' => "GitHub API returned HTTP {$httpCode} uploading {$filename}: " . substr((string) $responseBody, 0, 500)];
        return ['ok' => true];
    }
}
