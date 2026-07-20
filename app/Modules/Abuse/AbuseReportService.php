<?php
namespace App\Modules\Abuse;

use App\Support\DB;
use RuntimeException;
use Throwable;

class AbuseReportService
{
    public function __construct(private string $rdapBaseUrl = 'https://rdap.org/ip/')
    {
    }

    /** @return array{abuse_email:?string,network_name:?string,country:?string,handle:?string,rdap_error:?string} */
    public function lookupAbuseContact(string $ip): array
    {
        $result = ['abuse_email' => null, 'network_name' => null, 'country' => null, 'handle' => null, 'rdap_error' => null];
        try {
            $data = $this->rdapFetch($this->rdapBaseUrl . urlencode($ip));
            $result['network_name'] = $data['name'] ?? null;
            $result['country'] = $data['country'] ?? null;
            $result['handle'] = $data['handle'] ?? null;
            $result['abuse_email'] = $this->extractAbuseEmail($data);
        } catch (Throwable $e) {
            $result['rdap_error'] = $e->getMessage();
        }
        return $result;
    }

    /** @return array{ip:string,to:?string,subject:string,body:string,log_lines:array,network_name:?string,country:?string,rdap_error:?string} */
    public function buildDraft(string $ip, ?array $threatIp = null): array
    {
        $contact = $this->lookupAbuseContact($ip);
        $logLines = DB::select('SELECT l.*, s.name site_name FROM log_events l LEFT JOIN sites s ON s.id=l.site_id WHERE l.ip=? ORDER BY l.id DESC LIMIT 20', [$ip]);
        $hostname = @gethostname() ?: 'this server';

        $lines = [];
        $lines[] = 'Hello,';
        $lines[] = '';
        $lines[] = 'We are writing to report malicious activity originating from IP address ' . $ip
            . ', which appears to be assigned to your network' . ($contact['network_name'] ? ' (' . $contact['network_name'] . ')' : '') . '.';
        $lines[] = '';
        if ($threatIp) {
            $lines[] = 'Classification: ' . $threatIp['classification'] . ' (risk: ' . $threatIp['risk'] . ')';
            if (!empty($threatIp['notes'])) $lines[] = 'Notes: ' . $threatIp['notes'];
            $lines[] = '';
        }
        if ($logLines) {
            $lines[] = 'Below is a sample of the relevant log entries (most recent first, server time):';
            $lines[] = '';
            foreach ($logLines as $l) {
                $lines[] = '[' . $l['created_at'] . '] ' . ($l['method'] ?: '-') . ' ' . ($l['uri'] ?: '-') . ' (risk: ' . $l['risk'] . ', site: ' . ($l['site_name'] ?? 'unknown') . ')';
            }
            $lines[] = '';
        } else {
            $lines[] = 'No detailed request log entries are currently on file for this IP; the classification above is based on our own investigation of the incident.';
            $lines[] = '';
        }
        $lines[] = 'We kindly ask you to investigate and take appropriate action against the responsible party.';
        $lines[] = '';
        $lines[] = 'Regards,';
        $lines[] = $hostname;

        return [
            'ip' => $ip,
            'to' => $contact['abuse_email'],
            'subject' => 'Abuse report: malicious activity from ' . $ip,
            'body' => implode("\n", $lines),
            'log_lines' => $logLines,
            'network_name' => $contact['network_name'],
            'country' => $contact['country'],
            'rdap_error' => $contact['rdap_error'],
        ];
    }

    private function rdapFetch(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_HTTPHEADER => ['Accept: application/rdap+json'],
        ]);
        $response = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($errno) throw new RuntimeException('RDAP request failed: ' . $error);
        if ($httpCode >= 400) throw new RuntimeException('RDAP server returned HTTP ' . $httpCode);
        $decoded = json_decode((string) $response, true);
        if (!is_array($decoded)) throw new RuntimeException('RDAP response was not valid JSON.');
        return $decoded;
    }

    private function extractAbuseEmail(array $data): ?string
    {
        foreach ($data['entities'] ?? [] as $entity) {
            if (in_array('abuse', $entity['roles'] ?? [], true)) {
                $email = $this->emailFromVcard($entity['vcardArray'] ?? null);
                if ($email) return $email;
            }
            foreach ($entity['entities'] ?? [] as $sub) {
                if (in_array('abuse', $sub['roles'] ?? [], true)) {
                    $email = $this->emailFromVcard($sub['vcardArray'] ?? null);
                    if ($email) return $email;
                }
            }
        }
        return null;
    }

    private function emailFromVcard(?array $vcardArray): ?string
    {
        if (!$vcardArray || !isset($vcardArray[1]) || !is_array($vcardArray[1])) return null;
        foreach ($vcardArray[1] as $field) {
            if (($field[0] ?? '') === 'email' && !empty($field[3])) return (string) $field[3];
        }
        return null;
    }
}
