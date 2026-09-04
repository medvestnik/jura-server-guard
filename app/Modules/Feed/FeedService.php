<?php
namespace App\Modules\Feed;

use App\Modules\Incidents\IncidentImportService;
use App\Support\DB;
use Throwable;

/**
 * Pulls signatures/incidents from the public jura-server-guard-signatures-feed
 * repository (or a fork of it — see config('guard.feed_repo')).
 *
 * Trust model (deliberately checksum-only for now, no signature verification):
 *   - The panel NEVER reads the feed repo's default branch. It only ever fetches
 *     a specific GitHub Release by tag ("pinned" in the settings table), found
 *     via the GitHub Releases API.
 *   - The downloaded release bundle is verified against the .sha256 sidecar
 *     asset published alongside it.
 *   - Each incident file's own sha256 (recorded in feed.json) is re-verified
 *     before import, independent of the bundle-level checksum.
 *   - Signatures imported from the feed always land with enabled=0 and
 *     review_status='pending_feed_review' — never live until an admin approves
 *     them via /signatures (same guard:signature-enable path as any other
 *     signature). This is the safety net that a compromised feed release, or
 *     just an over-broad new signature, cannot silently go critical fleet-wide.
 */
class FeedService
{
    private const SETTING_PINNED_TAG = 'feed_pinned_tag';
    private const SETTING_LATEST_KNOWN_TAG = 'feed_latest_known_tag';
    private const SETTING_LAST_CHECKED_AT = 'feed_last_checked_at';
    private const SETTING_LAST_FETCHED_AT = 'feed_last_fetched_at';

    public function repo(): string
    {
        return trim((string) config('guard.feed_repo', 'medvestnik/jura-server-guard-signatures-feed'), '/');
    }

    public function pinnedTag(): ?string
    {
        return $this->setting(self::SETTING_PINNED_TAG);
    }

    public function latestKnownTag(): ?string
    {
        return $this->setting(self::SETTING_LATEST_KNOWN_TAG);
    }

    public function lastCheckedAt(): ?string
    {
        return $this->setting(self::SETTING_LAST_CHECKED_AT);
    }

    public function lastFetchedAt(): ?string
    {
        return $this->setting(self::SETTING_LAST_FETCHED_AT);
    }

    /** Lists incidents known from the currently pinned release, newest first. */
    public function knownIncidents(): array
    {
        return DB::select('SELECT * FROM feed_incidents ORDER BY id DESC');
    }

    /**
     * Ask GitHub which release tag is currently "latest" for the feed repo.
     * Does NOT download or change anything pinned — purely informational, so
     * an admin can see "a new release is available" before choosing to fetch it.
     *
     * @return array{ok:bool,tag?:string,published_at?:string,error?:string}
     */
    public function checkLatest(): array
    {
        $result = $this->githubGet("https://api.github.com/repos/{$this->repo()}/releases/latest");
        if (!$result['ok']) return $result;
        $tag = (string) ($result['data']['tag_name'] ?? '');
        if ($tag === '') return ['ok' => false, 'error' => 'GitHub response had no tag_name.'];
        $this->putSetting(self::SETTING_LATEST_KNOWN_TAG, $tag);
        $this->putSetting(self::SETTING_LAST_CHECKED_AT, now());
        return ['ok' => true, 'tag' => $tag, 'published_at' => (string) ($result['data']['published_at'] ?? '')];
    }

    /**
     * Downloads and verifies one release, pins it, and upserts feed_incidents
     * from its feed.json. Never imports anything into malware_signatures by
     * itself — that is a separate, explicit step per incident (importIncident()).
     *
     * @return array{ok:bool,error?:string,summary?:array}
     */
    public function fetchRelease(string $tag): array
    {
        $tag = trim($tag);
        if ($tag === '' || !preg_match('/^[A-Za-z0-9._-]+$/', $tag)) return ['ok' => false, 'error' => 'Invalid release tag.'];

        $releaseInfo = $this->githubGet("https://api.github.com/repos/{$this->repo()}/releases/tags/{$tag}");
        if (!$releaseInfo['ok']) return $releaseInfo;

        $assets = [];
        foreach ((array) ($releaseInfo['data']['assets'] ?? []) as $a) {
            $assets[(string) ($a['name'] ?? '')] = (string) ($a['browser_download_url'] ?? '');
        }
        $bundleName = "feed-bundle-{$tag}.tar.gz";
        $bundleUrl = $assets[$bundleName] ?? null;
        $checksumUrl = $assets["{$bundleName}.sha256"] ?? null;
        if (!$bundleUrl || !$checksumUrl) {
            return ['ok' => false, 'error' => "Release {$tag} is missing {$bundleName} and/or its .sha256 asset."];
        }

        $dir = storage_path("feed/{$tag}");
        if (!is_dir($dir) && !mkdir($dir, 0750, true) && !is_dir($dir)) {
            return ['ok' => false, 'error' => "Could not create {$dir}."];
        }
        $bundlePath = "{$dir}/{$bundleName}";
        $checksumPath = "{$bundlePath}.sha256";

        $dl = $this->downloadToFile($bundleUrl, $bundlePath);
        if (!$dl['ok']) return $dl;
        $dl = $this->downloadToFile($checksumUrl, $checksumPath);
        if (!$dl['ok']) return $dl;

        $expected = strtolower(trim(explode(' ', trim((string) file_get_contents($checksumPath)))[0] ?? ''));
        $actual = hash_file('sha256', $bundlePath);
        if (!$expected || !hash_equals($expected, (string) $actual)) {
            return ['ok' => false, 'error' => "Bundle checksum mismatch for {$tag}: expected {$expected}, got {$actual}. Refusing to extract."];
        }

        $extractDir = "{$dir}/extracted";
        if (!is_dir($extractDir) && !mkdir($extractDir, 0750, true) && !is_dir($extractDir)) {
            return ['ok' => false, 'error' => "Could not create {$extractDir}."];
        }
        try {
            $phar = new \PharData($bundlePath);
            $phar->extractTo($extractDir, null, true);
        } catch (Throwable $e) {
            return ['ok' => false, 'error' => "Failed to extract bundle: {$e->getMessage()}"];
        }

        $manifestPath = "{$extractDir}/feed.json";
        if (!is_file($manifestPath)) return ['ok' => false, 'error' => 'feed.json missing from bundle.'];
        $manifest = json_decode((string) file_get_contents($manifestPath), true);
        if (!is_array($manifest) || ($manifest['feed_format'] ?? null) !== 'jura-server-guard-feed') {
            return ['ok' => false, 'error' => 'feed.json is malformed or has an unrecognized feed_format.'];
        }

        $summary = ['created' => 0, 'updated' => 0, 'checksum_mismatches' => []];
        foreach ((array) ($manifest['incidents'] ?? []) as $entry) {
            $incidentId = (string) ($entry['id'] ?? '');
            $relFile = (string) ($entry['file'] ?? '');
            $expectedSha = strtolower((string) ($entry['sha256'] ?? ''));
            if ($incidentId === '' || $relFile === '') continue;

            $fullFile = "{$extractDir}/{$relFile}";
            if (!is_file($fullFile) || strtolower((string) hash_file('sha256', $fullFile)) !== $expectedSha) {
                $summary['checksum_mismatches'][] = $incidentId;
                continue; // never register an incident whose file doesn't match the manifest's own hash
            }

            $existing = DB::first('SELECT id, import_status FROM feed_incidents WHERE incident_id=?', [$incidentId]);
            $fields = [
                $tag, $relFile, $expectedSha,
                (string) ($entry['title'] ?? ''), (string) ($entry['severity'] ?? ''),
                json_encode($entry['signature_slugs'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            ];
            if ($existing) {
                DB::statement('UPDATE feed_incidents SET release_tag=?,file_path=?,sha256=?,title=?,severity=?,signature_slugs_json=?,updated_at=? WHERE id=?', [...$fields, now(), $existing['id']]);
                $summary['updated']++;
            } else {
                DB::insert('INSERT INTO feed_incidents (incident_id,release_tag,file_path,sha256,title,severity,signature_slugs_json,import_status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)', [$incidentId, ...$fields, 'not_imported', now(), now()]);
                $summary['created']++;
            }
        }

        $this->putSetting(self::SETTING_PINNED_TAG, $tag);
        $this->putSetting(self::SETTING_LAST_FETCHED_AT, now());

        return ['ok' => true, 'summary' => $summary];
    }

    /**
     * Imports one already-fetched feed incident through IncidentImportService,
     * forcing every signature it brings to land disabled and pending review.
     *
     * @return array{ok:bool,error?:string,summary?:array,dry_run?:bool}
     */
    public function importIncident(string $incidentId, bool $dryRun = true): array
    {
        $row = DB::first('SELECT * FROM feed_incidents WHERE incident_id=?', [$incidentId]);
        if (!$row) return ['ok' => false, 'error' => "Unknown feed incident '{$incidentId}' — fetch a release first."];

        $fullFile = storage_path("feed/{$row['release_tag']}/extracted/{$row['file_path']}");
        if (!is_file($fullFile)) return ['ok' => false, 'error' => "Incident file missing on disk: {$fullFile}. Re-fetch the release."];
        if (strtolower((string) hash_file('sha256', $fullFile)) !== strtolower((string) $row['sha256'])) {
            return ['ok' => false, 'error' => 'Incident file on disk no longer matches its recorded checksum — refusing to import.'];
        }

        $data = json_decode((string) file_get_contents($fullFile), true);
        if (!is_array($data)) return ['ok' => false, 'error' => 'Incident file is not valid JSON.'];

        $result = (new IncidentImportService())->import($data, $dryRun, "feed:{$row['release_tag']}:{$row['file_path']}", true, (string) $row['release_tag']);
        if ($result['ok'] && !$dryRun) {
            DB::statement("UPDATE feed_incidents SET import_status='imported', imported_at=?, updated_at=? WHERE id=?", [now(), now(), $row['id']]);
        }
        return $result;
    }

    // --- internals -----------------------------------------------------

    private function setting(string $key): ?string
    {
        $row = DB::first('SELECT value FROM settings WHERE ' . DB::quoteIdentifier('key') . '=?', [$key]);
        return $row['value'] ?? null;
    }

    private function putSetting(string $key, string $value): void
    {
        $keyCol = DB::quoteIdentifier('key');
        if (DB::first("SELECT id FROM settings WHERE $keyCol=?", [$key])) {
            DB::statement("UPDATE settings SET value=?,updated_at=? WHERE $keyCol=?", [$value, now(), $key]);
        } else {
            DB::insert("INSERT INTO settings ($keyCol,value,created_at,updated_at) VALUES (?,?,?,?)", [$key, $value, now(), now()]);
        }
    }

    /** @return array{ok:bool,data?:array,error?:string} */
    private function githubGet(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_HTTPHEADER => ['User-Agent: jura-server-guard-feed-client', 'Accept: application/vnd.github+json'],
        ]);
        $body = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($errno) return ['ok' => false, 'error' => "cURL error contacting GitHub: {$error}"];
        if ($httpCode === 403 || $httpCode === 429) return ['ok' => false, 'error' => "GitHub API rate-limited or forbidden (HTTP {$httpCode}). Try again later."];
        if ($httpCode !== 200) return ['ok' => false, 'error' => "GitHub API returned HTTP {$httpCode} for {$url}."];
        $decoded = json_decode((string) $body, true);
        if (!is_array($decoded)) return ['ok' => false, 'error' => 'GitHub API returned unparsable JSON.'];
        return ['ok' => true, 'data' => $decoded];
    }

    /** @return array{ok:bool,error?:string} */
    private function downloadToFile(string $url, string $destination): array
    {
        $fh = fopen($destination, 'wb');
        if (!$fh) return ['ok' => false, 'error' => "Could not open {$destination} for writing."];
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FILE => $fh,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 60,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_HTTPHEADER => ['User-Agent: jura-server-guard-feed-client'],
        ]);
        $ok = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        fclose($fh);
        if (!$ok || $errno) { @unlink($destination); return ['ok' => false, 'error' => "Download failed for {$url}: {$error}"]; }
        if ($httpCode !== 200) { @unlink($destination); return ['ok' => false, 'error' => "Download of {$url} returned HTTP {$httpCode}."]; }
        return ['ok' => true];
    }
}
