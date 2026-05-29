<?php
namespace App\Modules\Rules;

use App\Support\DB;

class RuleRepository
{
    public function seedDefaults(): void
    {
        $rules = require base_path('rules/default-rules.php');
        foreach ($rules['malware_strings'] as $r) $this->insertRule($r['name'], $r['risk'], $r['type'], $r['pattern'], 'string', $r['name']);
        foreach ($rules['php_functions'] as $fn) $this->insertRule('PHP function: ' . $fn, $fn === 'base64_decode(' ? 'medium' : 'high', 'suspicious_php', $fn, 'string', 'Suspicious PHP function. Combination scoring is applied by scanner.');
        foreach ($rules['suspicious_paths'] as $p) $this->insertRule('Suspicious path: ' . $p, 'high', 'suspicious_php', $p, 'path', 'PHP file in writable/upload/cache area.');
        foreach ($rules['suspicious_names'] as $n) $this->insertRule('Suspicious name: ' . $n, 'high', 'webshell', $n, 'path', 'Known malware filename.');
        $this->insertRule('32-char hex PHP filename', 'medium', 'suspicious_php', '/[a-f0-9]{32}\.php$/i', 'regex', 'Hex-like PHP filename.');
        foreach ($rules['allowlist'] as $p) $this->insertAllow('Built-in allowlist: ' . $p, $p, 'Known CMS/plugin false positive pattern.');
    }
    private function insertRule(string $name, string $risk, string $type, string $pattern, string $patternType, ?string $description): void
    {
        if (!DB::first('SELECT id FROM rules WHERE name = ? AND pattern = ?', [$name, $pattern])) DB::insert('INSERT INTO rules (name, description, risk, type, pattern, pattern_type, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,1,?,?)', [$name, $description, $risk, $type, $pattern, $patternType, now(), now()]);
    }
    private function insertAllow(string $name, string $path, string $reason): void
    {
        if (!DB::first('SELECT id FROM allowlist_rules WHERE path_pattern = ?', [$path])) DB::insert('INSERT INTO allowlist_rules (name, path_pattern, reason, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?)', [$name, $path, $reason, 1, now(), now()]);
    }
    public function enabledRules(): array { return DB::select('SELECT * FROM rules WHERE enabled = 1 ORDER BY risk DESC, name'); }
    public function allowlist(): array { return DB::select('SELECT * FROM allowlist_rules WHERE enabled = 1'); }
    public function isAllowed(string $path, ?string $sha256 = null): bool
    {
        foreach ($this->allowlist() as $rule) {
            if (!empty($rule['sha256']) && $sha256 && hash_equals($rule['sha256'], $sha256)) return true;
            if (!empty($rule['path_pattern']) && fnmatch($rule['path_pattern'], $path, FNM_PATHNAME | FNM_CASEFOLD)) return true;
        }
        return false;
    }
}
