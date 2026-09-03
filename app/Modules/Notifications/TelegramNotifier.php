<?php
namespace App\Modules\Notifications;

class TelegramNotifier
{
    public function enabled(): bool
    {
        return (bool) config('guard.telegram_enabled') && (string) config('guard.telegram_bot_token') !== '' && (string) config('guard.telegram_chat_id') !== '';
    }

    /** @return array{ok:bool,error?:string} */
    public function send(string $message): array
    {
        if (!$this->enabled()) return ['ok' => false, 'error' => 'Telegram notifications are disabled or not configured.'];
        $token = (string) config('guard.telegram_bot_token');
        $chatId = (string) config('guard.telegram_chat_id');
        $url = "https://api.telegram.org/bot{$token}/sendMessage";
        $payload = http_build_query(['chat_id' => $chatId, 'text' => $message, 'disable_web_page_preview' => true]);
        for ($attempt = 1; $attempt <= 2; $attempt++) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $payload,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_CONNECTTIMEOUT => 5,
            ]);
            $response = curl_exec($ch);
            $errno = curl_errno($ch);
            $error = curl_error($ch);
            $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($errno) return ['ok' => false, 'error' => "cURL error: $error"];
            $decoded = json_decode((string)$response, true);
            if ($httpCode === 200 && is_array($decoded) && !empty($decoded['ok'])) return ['ok' => true];

            $description = is_array($decoded) ? (string)($decoded['description'] ?? '') : '';
            $retryAfter = is_array($decoded) ? (int)($decoded['parameters']['retry_after'] ?? 0) : 0;
            if ($httpCode === 429 && $retryAfter > 0 && $attempt === 1) {
                sleep(min(15, max(1, $retryAfter)));
                continue;
            }
            $detail = $description !== '' ? $description : substr((string)$response, 0, 500);
            if ($retryAfter > 0) $detail .= " (retry after {$retryAfter}s)";
            return ['ok' => false, 'error' => "Telegram API returned HTTP $httpCode: {$detail}"];
        }
        return ['ok' => false, 'error' => 'Telegram delivery failed after retry.'];
    }
}
