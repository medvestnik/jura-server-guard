<?php
namespace App\Modules\Ai;

use RuntimeException;
use Throwable;

class AiClient
{
    public function __construct(
        private string $provider,
        private string $apiKey,
        private string $model,
        private ?string $baseUrl = null,
    ) {
    }

    public static function fromConfig(): ?self
    {
        $provider = config('guard.ai_provider', 'openai') === 'anthropic' ? 'anthropic' : 'openai';
        if ($provider === 'anthropic') {
            if (!config('guard.anthropic_enabled') || (string) config('guard.anthropic_api_key') === '') return null;
            return new self('anthropic', (string) config('guard.anthropic_api_key'), (string) config('guard.ai_model') ?: 'claude-sonnet-4-5');
        }
        if (!config('guard.openai_enabled') || (string) config('guard.openai_api_key') === '') return null;
        return new self('openai', (string) config('guard.openai_api_key'), (string) config('guard.ai_model') ?: 'gpt-4o-mini');
    }

    public function provider(): string { return $this->provider; }
    public function model(): string { return $this->model; }

    /**
     * @param array<int,array{role:string,content:string}> $messages
     * @param array<int,array{name:string,description:string,parameters:array}> $tools
     * @return array{content:?string,tool_calls:array<int,array{id:string,name:string,arguments:array}>,error:?string}
     */
    public function chat(array $messages, array $tools = [], ?string $system = null): array
    {
        try {
            return $this->provider === 'anthropic'
                ? $this->chatAnthropic($messages, $tools, $system)
                : $this->chatOpenAi($messages, $tools, $system);
        } catch (Throwable $e) {
            return ['content' => null, 'tool_calls' => [], 'error' => $e->getMessage()];
        }
    }

    private function chatOpenAi(array $messages, array $tools, ?string $system): array
    {
        $payload = ['model' => $this->model, 'messages' => []];
        if ($system !== null) $payload['messages'][] = ['role' => 'system', 'content' => $system];
        foreach ($messages as $m) $payload['messages'][] = $m;
        if ($tools) {
            $payload['tools'] = array_map(fn($t) => ['type' => 'function', 'function' => ['name' => $t['name'], 'description' => $t['description'], 'parameters' => $t['parameters']]], $tools);
        }
        $resp = $this->post(($this->baseUrl ?? 'https://api.openai.com') . '/v1/chat/completions', $payload, ['Authorization: Bearer ' . $this->apiKey]);
        $choice = $resp['choices'][0]['message'] ?? [];
        $toolCalls = [];
        foreach ($choice['tool_calls'] ?? [] as $tc) {
            $toolCalls[] = ['id' => $tc['id'] ?? '', 'name' => $tc['function']['name'] ?? '', 'arguments' => json_decode((string) ($tc['function']['arguments'] ?? '{}'), true) ?: []];
        }
        return ['content' => $choice['content'] ?? null, 'tool_calls' => $toolCalls, 'error' => null];
    }

    private function chatAnthropic(array $messages, array $tools, ?string $system): array
    {
        $payload = ['model' => $this->model, 'max_tokens' => 2048, 'messages' => $messages];
        if ($system !== null) $payload['system'] = $system;
        if ($tools) {
            $payload['tools'] = array_map(fn($t) => ['name' => $t['name'], 'description' => $t['description'], 'input_schema' => $t['parameters']], $tools);
        }
        $resp = $this->post(($this->baseUrl ?? 'https://api.anthropic.com') . '/v1/messages', $payload, ['x-api-key: ' . $this->apiKey, 'anthropic-version: 2023-06-01']);
        $content = ''; $toolCalls = [];
        foreach ($resp['content'] ?? [] as $block) {
            if (($block['type'] ?? '') === 'text') $content .= (string) ($block['text'] ?? '');
            if (($block['type'] ?? '') === 'tool_use') $toolCalls[] = ['id' => $block['id'] ?? '', 'name' => $block['name'] ?? '', 'arguments' => $block['input'] ?? []];
        }
        return ['content' => $content !== '' ? $content : null, 'tool_calls' => $toolCalls, 'error' => null];
    }

    private function post(string $url, array $payload, array $headers): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            CURLOPT_HTTPHEADER => array_merge(['Content-Type: application/json'], $headers),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 60,
            CURLOPT_CONNECTTIMEOUT => 10,
        ]);
        $response = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($errno) throw new RuntimeException('cURL error: ' . $error);
        $decoded = json_decode((string) $response, true);
        if ($httpCode >= 400) {
            $msg = $decoded['error']['message'] ?? substr((string) $response, 0, 500);
            throw new RuntimeException("AI API returned HTTP $httpCode: $msg");
        }
        return is_array($decoded) ? $decoded : [];
    }
}
