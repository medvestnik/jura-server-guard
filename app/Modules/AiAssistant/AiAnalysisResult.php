<?php
namespace App\Modules\AiAssistant;
class AiAnalysisResult { public function __construct(public string $risk='disabled', public float $confidence=0, public string $summary='AI analysis disabled', public array $raw=[]) {} }
