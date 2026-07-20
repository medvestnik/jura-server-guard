<?php
namespace App\Modules\Ai;

use App\Modules\Quarantine\QuarantineService;
use App\Support\DB;
use RuntimeException;
use Throwable;

class ChatService
{
    private const MUTATING_TOOLS = ['quarantine_finding', 'delete_finding', 'trust_ip'];
    private const MAX_TOOL_ITERATIONS = 4;

    public function __construct(private ?AiClient $client = null)
    {
    }

    public function history(int $adminUserId): array
    {
        return DB::select('SELECT * FROM ai_chat_messages WHERE admin_user_id=? ORDER BY id ASC', [$adminUserId]);
    }

    public function clear(int $adminUserId): void
    {
        DB::statement('DELETE FROM ai_chat_messages WHERE admin_user_id=?', [$adminUserId]);
    }

    /**
     * Sends a user message, runs the AI + read-only-tool loop, and stops at either a final
     * text reply or a pending mutating tool call awaiting explicit user confirmation.
     */
    public function send(int $adminUserId, string $userMessage): void
    {
        $client = $this->client ?? AiClient::fromConfig();
        $this->insert($adminUserId, 'user', $userMessage);
        if (!$client) {
            $this->insert($adminUserId, 'assistant', 'AI chat is not configured. Set an AI provider in .env (JURA_AI_CHAT_ENABLED plus JURA_OPENAI_ENABLED/JURA_OPENAI_API_KEY or JURA_ANTHROPIC_ENABLED/JURA_ANTHROPIC_API_KEY).');
            return;
        }

        $messages = $this->buildMessages($adminUserId);
        $tools = $this->toolDefinitions();
        $system = $this->systemPrompt();

        for ($i = 0; $i < self::MAX_TOOL_ITERATIONS; $i++) {
            $result = $client->chat($messages, $tools, $system);
            if ($result['error'] !== null) {
                $this->insert($adminUserId, 'assistant', 'AI request failed: ' . $result['error']);
                return;
            }
            if (empty($result['tool_calls'])) {
                $this->insert($adminUserId, 'assistant', (string) ($result['content'] ?? ''));
                return;
            }
            // Handle one tool call per turn to keep the confirmation flow simple to follow.
            $call = $result['tool_calls'][0];
            if (in_array($call['name'], self::MUTATING_TOOLS, true)) {
                $this->insert($adminUserId, 'assistant', (string) ($result['content'] ?? ''), $call['name'], $call['arguments'], 'pending');
                return;
            }
            $toolResult = $this->executeReadOnlyTool($call['name'], $call['arguments']);
            $messages[] = ['role' => 'assistant', 'content' => (string) ($result['content'] ?? ('Calling ' . $call['name'] . '...'))];
            $messages[] = ['role' => 'user', 'content' => 'Tool "' . $call['name'] . '" result:' . "\n" . json_encode($toolResult, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)];
        }
        $this->insert($adminUserId, 'assistant', 'Stopped after too many tool calls in a row; please refine your request.');
    }

    /** Executes a pending mutating tool call the user confirmed, or marks it cancelled without running anything. */
    public function resolvePending(int $messageId, bool $confirm): void
    {
        $msg = DB::first('SELECT * FROM ai_chat_messages WHERE id=?', [$messageId]);
        if (!$msg || $msg['tool_status'] !== 'pending') return;
        if (!$confirm) {
            DB::statement('UPDATE ai_chat_messages SET tool_status=? WHERE id=?', ['cancelled', $messageId]);
            return;
        }
        $args = json_decode((string) $msg['tool_arguments_json'], true) ?: [];
        try {
            $result = $this->executeMutatingTool((string) $msg['tool_name'], $args);
        } catch (Throwable $e) {
            $result = 'Error: ' . $e->getMessage();
        }
        DB::statement('UPDATE ai_chat_messages SET tool_status=?, tool_result=? WHERE id=?', ['confirmed', $result, $messageId]);
    }

    private function buildMessages(int $adminUserId): array
    {
        $messages = [];
        foreach ($this->history($adminUserId) as $r) {
            if ($r['role'] === 'user') {
                $messages[] = ['role' => 'user', 'content' => (string) $r['content']];
            } elseif ($r['role'] === 'assistant' && $r['tool_name'] === null) {
                $messages[] = ['role' => 'assistant', 'content' => (string) $r['content']];
            } elseif ($r['role'] === 'assistant' && $r['tool_status'] !== null) {
                $note = $r['tool_status'] === 'pending'
                    ? 'You proposed calling ' . $r['tool_name'] . ' with ' . $r['tool_arguments_json'] . '; it is awaiting user confirmation, do not propose it again.'
                    : ('You proposed calling ' . $r['tool_name'] . '; ' . ($r['tool_status'] === 'cancelled' ? 'the user cancelled this action.' : 'result: ' . (string) $r['tool_result']));
                $messages[] = ['role' => 'assistant', 'content' => $note];
            }
        }
        return $messages;
    }

    private function toolDefinitions(): array
    {
        return [
            ['name' => 'search_findings', 'description' => 'Search findings by filename/path substring, site name, user name, and/or risk. Returns up to 20 matches with id, path, risk, status, site, user.', 'parameters' => ['type' => 'object', 'properties' => [
                'query' => ['type' => 'string', 'description' => 'Substring to match against the file path or finding title'],
                'site' => ['type' => 'string'], 'user' => ['type' => 'string'],
                'risk' => ['type' => 'string', 'enum' => ['low', 'medium', 'high', 'critical']],
            ], 'required' => []]],
            ['name' => 'get_finding', 'description' => 'Get full details of one finding by id.', 'parameters' => ['type' => 'object', 'properties' => ['finding_id' => ['type' => 'integer']], 'required' => ['finding_id']]],
            ['name' => 'quarantine_finding', 'description' => "Move a finding's file to quarantine. Reversible. The user must explicitly confirm before this actually runs.", 'parameters' => ['type' => 'object', 'properties' => ['finding_id' => ['type' => 'integer']], 'required' => ['finding_id']]],
            ['name' => 'delete_finding', 'description' => "Permanently delete a finding's file. NOT reversible. The user must explicitly confirm before this actually runs.", 'parameters' => ['type' => 'object', 'properties' => ['finding_id' => ['type' => 'integer']], 'required' => ['finding_id']]],
            ['name' => 'trust_ip', 'description' => 'Add an IP address to the trusted IP whitelist so future alerts ignore it. The user must explicitly confirm before this actually runs.', 'parameters' => ['type' => 'object', 'properties' => ['ip' => ['type' => 'string'], 'label' => ['type' => 'string']], 'required' => ['ip']]],
        ];
    }

    private function executeReadOnlyTool(string $name, array $args): array
    {
        if ($name === 'search_findings') {
            $where = []; $params = [];
            if (!empty($args['query'])) { $where[] = '(f.path LIKE ? OR f.title LIKE ?)'; $params[] = '%' . $args['query'] . '%'; $params[] = '%' . $args['query'] . '%'; }
            if (!empty($args['site'])) { $where[] = 's.name = ?'; $params[] = $args['site']; }
            if (!empty($args['user'])) { $where[] = 'u.name = ?'; $params[] = $args['user']; }
            if (!empty($args['risk'])) { $where[] = 'f.risk = ?'; $params[] = $args['risk']; }
            $sql = 'SELECT f.id, f.path, f.risk, f.status, f.type, s.name site_name, u.name user_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id';
            if ($where) $sql .= ' WHERE ' . implode(' AND ', $where);
            $sql .= ' ORDER BY f.id DESC LIMIT 20';
            return DB::select($sql, $params);
        }
        if ($name === 'get_finding') {
            $f = DB::first('SELECT f.*, s.name site_name, u.name user_name FROM findings f LEFT JOIN sites s ON s.id=f.site_id LEFT JOIN users u ON u.id=s.server_user_id WHERE f.id=?', [(int) ($args['finding_id'] ?? 0)]);
            return $f ?: ['error' => 'not found'];
        }
        return ['error' => 'unknown tool: ' . $name];
    }

    private function executeMutatingTool(string $name, array $args): string
    {
        if ($name === 'quarantine_finding') {
            if (!config('guard.web_actions_enabled')) return 'Refused: web actions are disabled (JURA_WEB_ACTIONS_ENABLED=false).';
            $id = (int) ($args['finding_id'] ?? 0);
            (new QuarantineService())->quarantine($id, 'AI chat (confirmed by admin)');
            return 'Quarantined finding #' . $id . '.';
        }
        if ($name === 'delete_finding') {
            if (!config('guard.web_actions_enabled')) return 'Refused: web actions are disabled (JURA_WEB_ACTIONS_ENABLED=false).';
            $id = (int) ($args['finding_id'] ?? 0);
            (new QuarantineService())->delete($id, 'AI chat (confirmed by admin)');
            return 'Permanently deleted finding #' . $id . '.';
        }
        if ($name === 'trust_ip') {
            $ip = trim((string) ($args['ip'] ?? ''));
            if ($ip === '') throw new RuntimeException('Missing ip argument.');
            if (DB::first('SELECT id FROM trusted_ips WHERE ip=?', [$ip])) return 'IP ' . $ip . ' is already trusted.';
            DB::insert('INSERT INTO trusted_ips (ip,label,notes,created_at,updated_at) VALUES (?,?,?,?,?)', [$ip, (string) ($args['label'] ?? 'Added via AI chat'), 'Added via AI chat', now(), now()]);
            return 'Added ' . $ip . ' to the trusted IP list.';
        }
        throw new RuntimeException('Unknown tool: ' . $name);
    }

    private function systemPrompt(): string
    {
        return 'You are a security assistant embedded in Jura Server Guard, a hosting security panel. '
            . 'You can search findings, inspect one finding, quarantine a finding, permanently delete a '
            . "finding, and add an IP address to the trusted whitelist. quarantine_finding, delete_finding, "
            . 'and trust_ip are never executed immediately when you call them - the user always sees an '
            . 'explicit confirmation prompt first, so it is safe to propose them when you are confident that '
            . 'is what the user wants. Be concise. When you are not sure which finding(s) the user means, '
            . 'call search_findings first instead of guessing an id.';
    }

    private function insert(int $adminUserId, string $role, string $content, ?string $toolName = null, ?array $toolArgs = null, ?string $toolStatus = null): int
    {
        return DB::insert('INSERT INTO ai_chat_messages (admin_user_id,role,content,tool_name,tool_arguments_json,tool_status,created_at) VALUES (?,?,?,?,?,?,?)', [
            $adminUserId, $role, $content, $toolName, $toolArgs !== null ? json_encode($toolArgs, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null, $toolStatus, now(),
        ]);
    }
}
