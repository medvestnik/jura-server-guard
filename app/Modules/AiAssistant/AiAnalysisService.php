<?php
namespace App\Modules\AiAssistant;
use App\Support\DB;
class AiAnalysisService
{
    public function analyzeFinding(array $finding): AiAnalysisResult
    {
        if (!config('guard.openai_enabled')) return new AiAnalysisResult();
        $result = new AiAnalysisResult('needs_review', 0, 'OpenAI provider is architecturally prepared but disabled in MVP core.', ['finding_id'=>$finding['id'] ?? null]);
        DB::insert('INSERT INTO ai_analyses (finding_id,provider,model,risk,confidence,summary,raw_response,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)', [$finding['id'], 'openai', null, $result->risk, $result->confidence, $result->summary, json_encode($result->raw), now(), now()]);
        return $result;
    }
}
