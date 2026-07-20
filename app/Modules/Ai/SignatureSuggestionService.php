<?php
namespace App\Modules\Ai;

use App\Support\DB;
use RuntimeException;

class SignatureSuggestionService
{
    public function __construct(private ?AiClient $client = null)
    {
    }

    public function suggest(int $findingId): int
    {
        $f = DB::first('SELECT * FROM findings WHERE id=?', [$findingId]);
        if (!$f) throw new RuntimeException('Finding not found.');
        $client = $this->client ?? (config('guard.ai_signatures_enabled') ? AiClient::fromConfig() : null);
        if (!$client) {
            return $this->insert($findingId, $f, null, null, 'draft', 'Draft from finding ' . $findingId, $f['risk'], $f['type'], 'combo', '{}', 'AI signatures are disabled or no AI provider is configured in settings; draft placeholder created for manual review.');
        }

        $content = ($f['path'] && is_readable($f['path'])) ? (string) file_get_contents($f['path'], false, null, 0, 8000) : '';
        $system = 'You are a malware/webshell signature analyst for a PHP hosting security scanner. Given a suspicious'
            . ' file finding, propose ONE signature that would catch this exact file and close variants without'
            . ' matching legitimate site code. Respond with ONLY strict JSON, no markdown fences, no commentary,'
            . ' matching this exact shape: {"name":string,"risk":"low|medium|high|critical","type":string,'
            . '"pattern_type":"hash|combo|regex|substring","pattern_json":object,"explanation":string}.'
            . ' Prefer "hash" (pattern_json={"sha256":["<the given sha256>"]}) when you are not confident about a'
            . ' broader pattern; use "combo" with distinctive substrings/regexes only when you can name specific'
            . ' strings that are very unlikely to appear in legitimate code.';
        $user = "Path: {$f['path']}\nSHA256: {$f['sha256']}\nCurrent finding risk/type/title: {$f['risk']} / {$f['type']} / {$f['title']}\n\nFile content (may be truncated):\n```\n{$content}\n```";
        $result = $client->chat([['role' => 'user', 'content' => $user]], [], $system);

        if ($result['error'] !== null) {
            return $this->insert($findingId, $f, $client->provider(), $client->model(), 'error', 'AI request failed', $f['risk'], $f['type'], 'hash', json_encode(['sha256' => [$f['sha256']]]), 'AI request failed: ' . $result['error']);
        }
        $parsed = $this->parseJson((string) $result['content']);
        if ($parsed === null) {
            return $this->insert($findingId, $f, $client->provider(), $client->model(), 'needs_review', 'AI suggestion (unparsed)', $f['risk'], $f['type'], 'hash', json_encode(['sha256' => [$f['sha256']]]), 'Could not parse the AI response as JSON. Raw response: ' . substr((string) $result['content'], 0, 4000));
        }
        return $this->insert(
            $findingId, $f, $client->provider(), $client->model(), 'ready',
            (string) ($parsed['name'] ?? ('AI suggestion for finding ' . $findingId)),
            in_array($parsed['risk'] ?? '', ['low', 'medium', 'high', 'critical'], true) ? $parsed['risk'] : $f['risk'],
            (string) ($parsed['type'] ?? $f['type']),
            in_array($parsed['pattern_type'] ?? '', ['hash', 'combo', 'regex', 'substring', 'structural'], true) ? $parsed['pattern_type'] : 'hash',
            is_array($parsed['pattern_json'] ?? null) ? json_encode($parsed['pattern_json'], JSON_UNESCAPED_SLASHES) : json_encode(['sha256' => [$f['sha256']]]),
            (string) ($parsed['explanation'] ?? '')
        );
    }

    private function parseJson(string $text): ?array
    {
        $text = trim($text);
        $text = trim((string) preg_replace('/^```(?:json)?|```$/m', '', $text));
        $decoded = json_decode($text, true);
        return is_array($decoded) ? $decoded : null;
    }

    private function insert(int $findingId, array $f, ?string $provider, ?string $model, string $status, string $name, string $risk, string $type, string $patternType, string $patternJson, string $explanation): int
    {
        return DB::insert('INSERT INTO signature_suggestions (finding_id,source_file_path,source_file_sha256,ai_provider,model,status,suggested_name,suggested_risk,suggested_type,suggested_pattern_type,suggested_pattern_json,explanation,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [
            $findingId, $f['path'], $f['sha256'], $provider, $model, $status, $name, $risk, $type, $patternType, $patternJson, $explanation, now(), now(),
        ]);
    }
}
