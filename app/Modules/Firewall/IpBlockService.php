<?php
namespace App\Modules\Firewall;

use App\Support\DB;
use RuntimeException;

class IpBlockService
{
    public function status(string $ip): array
    {
        $ip = $this->validateIp($ip);
        $backend = $this->resolveBackend($ip);
        if ($backend === null) {
            return ['blocked'=>false, 'available'=>false, 'backend'=>null, 'error'=>'Neither active firewalld nor iptables is available.'];
        }
        return $backend === 'firewalld' ? $this->firewalldStatus($ip) : $this->iptablesStatus($ip);
    }

    public function block(string $ip): array
    {
        $ip = $this->validateIp($ip);
        if (DB::first('SELECT id FROM trusted_ips WHERE ip=?', [$ip])) {
            throw new RuntimeException('Refusing to block an IP that is in the trusted list.');
        }

        $backend = $this->resolveBackend($ip);
        if ($backend === null) throw new RuntimeException('Neither active firewalld nor iptables is available.');
        return $backend === 'firewalld' ? $this->blockWithFirewalld($ip) : $this->blockWithIptables($ip);
    }

    private function firewalldStatus(string $ip): array
    {
        $zone = $this->zone();
        $runtime = $this->run([$this->firewalldBinary(), '--quiet', '--zone='.$zone, '--query-source='.$ip]);
        $permanent = $this->run([$this->firewalldBinary(), '--quiet', '--permanent', '--zone='.$zone, '--query-source='.$ip]);
        return [
            'blocked'=>$runtime['code'] === 0 || $permanent['code'] === 0,
            'available'=>true,
            'runtime'=>$runtime['code'] === 0,
            'permanent'=>$permanent['code'] === 0,
            'backend'=>'firewalld',
            'zone'=>$zone,
            'error'=>null,
        ];
    }

    private function blockWithFirewalld(string $ip): array
    {
        $zone = $this->zone();
        $current = $this->firewalldStatus($ip);
        if (!$current['permanent']) {
            $result = $this->run([$this->firewalldBinary(), '--permanent', '--zone='.$zone, '--add-source='.$ip]);
            if ($result['code'] !== 0) throw new RuntimeException($result['output'] ?: 'Failed to add the permanent firewalld rule.');
        }
        if (!$current['runtime']) {
            $result = $this->run([$this->firewalldBinary(), '--zone='.$zone, '--add-source='.$ip]);
            if ($result['code'] !== 0) throw new RuntimeException($result['output'] ?: 'Failed to add the runtime firewalld rule.');
        }
        return $this->firewalldStatus($ip);
    }

    private function iptablesStatus(string $ip): array
    {
        $binary = $this->iptablesBinary($ip);
        $runtime = $this->run([$binary, '-C', 'INPUT', '-s', $ip, '-j', 'DROP']);
        $rulesFile = $this->iptablesRulesFile($ip);
        return [
            'blocked'=>$runtime['code'] === 0,
            'available'=>true,
            'runtime'=>$runtime['code'] === 0,
            'permanent'=>$this->savedRuleExists($rulesFile, $ip),
            'backend'=>filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'ip6tables' : 'iptables',
            'rules_file'=>$rulesFile,
            'error'=>null,
        ];
    }

    private function blockWithIptables(string $ip): array
    {
        $current = $this->iptablesStatus($ip);
        if (!$current['runtime']) {
            $result = $this->run([$this->iptablesBinary($ip), '-I', 'INPUT', '1', '-s', $ip, '-j', 'DROP']);
            if ($result['code'] !== 0) throw new RuntimeException($result['output'] ?: 'Failed to add the runtime iptables rule.');
        }
        $this->persistIptables($ip);
        return $this->iptablesStatus($ip);
    }

    private function persistIptables(string $ip): void
    {
        $init = $this->iptablesInitBinary($ip);
        if ($this->isExecutable($init)) {
            $saved = $this->run([$init, 'save']);
            if ($saved['code'] !== 0) throw new RuntimeException($saved['output'] ?: 'Runtime rule was added, but iptables persistence failed.');
        } else {
            $saveBinary = $this->iptablesSaveBinary($ip);
            if (!$this->isExecutable($saveBinary)) throw new RuntimeException('Runtime rule was added, but iptables-save is not available.');
            $saved = $this->run([$saveBinary]);
            if ($saved['code'] !== 0 || $saved['stdout'] === '') throw new RuntimeException($saved['output'] ?: 'Runtime rule was added, but iptables-save failed.');
            $this->writeRulesFile($this->iptablesRulesFile($ip), $saved['stdout']);
        }

        if (config('guard.iptables_enable_service')) $this->enableIptablesRestoreService($ip);
    }

    private function writeRulesFile(string $path, string $content): void
    {
        $dir = dirname($path);
        if (!is_dir($dir) || (!is_writable($dir) && !(is_file($path) && is_writable($path)))) {
            throw new RuntimeException('Runtime rule was added, but the persistent iptables rules file is not writable: '.$path);
        }
        $tmp = tempnam($dir, '.jura-iptables-');
        if ($tmp === false) throw new RuntimeException('Failed to create a temporary iptables rules file.');
        $mode = is_file($path) ? (fileperms($path) & 0777) : 0600;
        if (file_put_contents($tmp, $content, LOCK_EX) === false || !@chmod($tmp, $mode) || !@rename($tmp, $path)) {
            @unlink($tmp);
            throw new RuntimeException('Runtime rule was added, but the persistent iptables rules file could not be updated.');
        }
    }

    private function enableIptablesRestoreService(string $ip): void
    {
        $systemctl = (string) config('guard.systemctl_cmd');
        if (!$this->isExecutable($systemctl)) return;
        $service = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'ip6tables.service' : 'iptables.service';
        $exists = $this->run([$systemctl, 'list-unit-files', $service, '--no-legend']);
        if ($exists['code'] !== 0 || !str_contains($exists['stdout'], $service)) return;
        $enabled = $this->run([$systemctl, 'is-enabled', $service]);
        if ($enabled['code'] === 0) return;
        $result = $this->run([$systemctl, 'enable', $service]);
        if ($result['code'] !== 0) throw new RuntimeException($result['output'] ?: 'Runtime rule was added and saved, but the iptables restore service could not be enabled.');
    }

    private function savedRuleExists(string $path, string $ip): bool
    {
        if (!is_readable($path)) return false;
        $rules = (string) file_get_contents($path);
        foreach (preg_split('/\R/', $rules) ?: [] as $line) {
            if (!str_starts_with($line, '-A INPUT ')) continue;
            if (!preg_match('/(?:^|\s)-j\s+DROP(?:\s|$)/', $line)) continue;
            if (preg_match('/(?:^|\s)-s\s+'.preg_quote($ip, '/').'(?:\/(?:32|128))?(?:\s|$)/', $line)) return true;
        }
        return false;
    }

    private function resolveBackend(string $ip): ?string
    {
        $configured = strtolower(trim((string) config('guard.firewall_backend')));
        if (!in_array($configured, ['auto','firewalld','iptables'], true)) throw new RuntimeException('Invalid firewall backend. Use auto, firewalld, or iptables.');
        if ($configured === 'firewalld') return $this->firewalldUsable() ? 'firewalld' : null;
        if ($configured === 'iptables') return $this->iptablesAvailable($ip) ? 'iptables' : null;
        if ($this->firewalldUsable()) return 'firewalld';
        return $this->iptablesAvailable($ip) ? 'iptables' : null;
    }

    private function firewalldUsable(): bool
    {
        if (!$this->isExecutable($this->firewalldBinary())) return false;
        return $this->run([$this->firewalldBinary(), '--state'])['code'] === 0;
    }

    private function iptablesAvailable(string $ip): bool
    {
        $key = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'guard.ip6tables_cmd' : 'guard.iptables_cmd';
        return $this->isExecutable((string)config($key));
    }

    private function validateIp(string $ip): string
    {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) throw new RuntimeException('Invalid IP address.');
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            throw new RuntimeException('Refusing to block a private, loopback, link-local, or reserved IP address.');
        }
        return $ip;
    }

    private function zone(): string
    {
        $zone = (string) config('guard.firewall_block_zone');
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $zone)) throw new RuntimeException('Invalid firewall block zone.');
        return $zone;
    }

    private function iptablesBinary(string $ip): string
    {
        $binary = (string) config(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'guard.ip6tables_cmd' : 'guard.iptables_cmd');
        if (!$this->isExecutable($binary)) throw new RuntimeException(basename($binary ?: 'iptables').' is not available.');
        return $binary;
    }

    private function firewalldBinary(): string { return (string) config('guard.firewall_cmd'); }
    private function iptablesSaveBinary(string $ip): string { return (string) config(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'guard.ip6tables_save_cmd' : 'guard.iptables_save_cmd'); }
    private function iptablesInitBinary(string $ip): string { return (string) config(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'guard.ip6tables_init_cmd' : 'guard.iptables_init_cmd'); }
    private function iptablesRulesFile(string $ip): string { return (string) config(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'guard.ip6tables_rules_file' : 'guard.iptables_rules_file'); }
    private function isExecutable(string $path): bool { return $path !== '' && is_file($path) && is_executable($path); }

    private function run(array $command): array
    {
        $pipes = [];
        $process = @proc_open($command, [1=>['pipe','w'], 2=>['pipe','w']], $pipes);
        if (!is_resource($process)) return ['code'=>127, 'stdout'=>'', 'stderr'=>'Unable to start firewall command.', 'output'=>'Unable to start firewall command.'];
        $stdout = stream_get_contents($pipes[1]); fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
        return ['code'=>proc_close($process), 'stdout'=>trim($stdout), 'stderr'=>trim($stderr), 'output'=>trim($stdout."\n".$stderr)];
    }
}
