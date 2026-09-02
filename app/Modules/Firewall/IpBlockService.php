<?php
namespace App\Modules\Firewall;

use App\Support\DB;
use RuntimeException;

class IpBlockService
{
    public function status(string $ip): array
    {
        $ip = $this->validateIp($ip);
        $zone = $this->zone();
        if (!$this->firewallCmdAvailable()) {
            return ['blocked' => false, 'available' => false, 'zone' => $zone, 'error' => 'firewall-cmd is not available.'];
        }

        $runtime = $this->run([$this->binary(), '--quiet', '--zone='.$zone, '--query-source='.$ip]);
        $permanent = $this->run([$this->binary(), '--quiet', '--permanent', '--zone='.$zone, '--query-source='.$ip]);
        return [
            'blocked' => $runtime['code'] === 0 || $permanent['code'] === 0,
            'available' => true,
            'runtime' => $runtime['code'] === 0,
            'permanent' => $permanent['code'] === 0,
            'zone' => $zone,
            'error' => null,
        ];
    }

    public function block(string $ip): array
    {
        $ip = $this->validateIp($ip);
        if (DB::first('SELECT id FROM trusted_ips WHERE ip=?', [$ip])) {
            throw new RuntimeException('Refusing to block an IP that is in the trusted list.');
        }
        if (!$this->firewallCmdAvailable()) throw new RuntimeException('firewall-cmd is not available.');

        $zone = $this->zone();
        $current = $this->status($ip);
        if (!($current['permanent'] ?? false)) {
            $result = $this->run([$this->binary(), '--permanent', '--zone='.$zone, '--add-source='.$ip]);
            if ($result['code'] !== 0) throw new RuntimeException($result['output'] ?: 'Failed to add the permanent firewall rule.');
        }
        if (!($current['runtime'] ?? false)) {
            $result = $this->run([$this->binary(), '--zone='.$zone, '--add-source='.$ip]);
            if ($result['code'] !== 0) throw new RuntimeException($result['output'] ?: 'Failed to add the runtime firewall rule.');
        }
        return $this->status($ip);
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

    private function binary(): string { return (string) config('guard.firewall_cmd'); }
    private function firewallCmdAvailable(): bool { return is_file($this->binary()) && is_executable($this->binary()); }

    private function run(array $command): array
    {
        $pipes = [];
        $process = @proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) return ['code' => 127, 'output' => 'Unable to start firewall-cmd.'];
        $stdout = stream_get_contents($pipes[1]); fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
        return ['code' => proc_close($process), 'output' => trim($stdout."\n".$stderr)];
    }
}
