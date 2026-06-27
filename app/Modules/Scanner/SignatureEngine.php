<?php
namespace App\Modules\Scanner;

use App\Support\DB;

class SignatureEngine
{
    public function enabledSignatures(): array
    {
        $builtins = $this->builtinSignatures();
        try { $db = DB::select("SELECT * FROM malware_signatures WHERE enabled=1 AND source <> 'builtin' ORDER BY id"); } catch (\Throwable) { $db = []; }
        return array_merge($builtins, $db);
    }

    public function builtinSignatures(): array
    {
        return [[
            'id'=>null,'name'=>'remote_eval_loader_php_input_curl','slug'=>'remote_eval_loader_php_input_curl','risk'=>'critical','type'=>'webshell','pattern_type'=>'combo','source'=>'builtin','description'=>'Remote eval loader reading php://input, decoding/transforming payloads, requesting remote content through curl_exec, then evaling response.','target_extensions'=>'["php","phtml","inc"]','pattern_json'=>json_encode(['all'=>['php://input','curl_exec'],'regex_all'=>['/\beval\s*(?:\/\*.*?\*\/\s*)?\(/is'],'any'=>['base64_decode','str_rot13','hex2bin','expected_hash','md5(md5('],'regex_any'=>['/\bunpack\s*\(\s*[\'\"]H\*/i']], JSON_UNESCAPED_SLASHES)
        ],[
            'id'=>null,'name'=>'php_file_manager_shell_array_rot13_pack','slug'=>'php_file_manager_shell_array_rot13_pack','risk'=>'critical','type'=>'webshell','pattern_type'=>'combo','source'=>'builtin','description'=>'Chinese-style PHP file manager shell using ARRAY parameter, rot13/pack/json decode gate, md5(md5()) and file management actions.','target_extensions'=>'["php","phtml","inc"]','pattern_json'=>json_encode(['regex_all'=>['/(?:\$\{\s*[\'\"]_GET[\'\"]\s*\}|\$_GET)\s*\[\s*[\'\"]ARRAY[\'\"]\s*\]/i','/\bstr_rot13\s*\(/i','/\bpack\s*\(/i','/\bjson_decode\s*\(/i','/\bmd5\s*\(\s*md5\s*\(/i'],'required_groups'=>[['min'=>2,'any'=>['chmod(','rename(','unlink(','fopen(','fwrite(','move_uploaded_file(','file_get_contents(','enctype="multipart/form-data"','enctype=\'multipart/form-data\''],'regex_any'=>['/<input\b[^>]*type\s*=\s*[\'\"]?file/i']]]], JSON_UNESCAPED_SLASHES)
        ],[
            'id'=>null,'name'=>'fake_cms_env_probe_tree_404sbg','slug'=>'fake_cms_env_probe_tree_404sbg','risk'=>'critical','type'=>'structural','pattern_type'=>'structural','source'=>'builtin','description'=>'Fake CMS/env probe tree with 404SBG, platform-name directories, .txt404 folders, and nested base64 loaders.','target_extensions'=>'[]','pattern_json'=>json_encode(['directory_names'=>['404SBG'],'path_contains'=>['WHMCS','Joomla','Drupal','OpenCart','PrestaShop','env','accesshash','admin-env','.txt404'],'regex_any'=>['/(include_once|require_once)\s+base64_decode\s*\(/i','/eval\s*\(\s*base64_decode\s*\(/i']], JSON_UNESCAPED_SLASHES)
        ]];
    }

    public function match(array $sig, string $path, string $relative, array $meta, string $content, string $root = ''): ?array
    {
        if (!$this->targets($sig, $path, $relative, $meta)) return null;
        $pattern = json_decode((string)($sig['pattern_json'] ?? '{}'), true) ?: [];
        $matched = [];
        $type = $sig['pattern_type'] ?? 'substring';
        $ok = match ($type) {
            'regex' => $this->matchRegex((string)($pattern['regex'] ?? $sig['pattern'] ?? ''), $content, $matched),
            'hash' => in_array(strtolower((string)($meta['sha256'] ?? '')), array_map('strtolower', (array)($pattern['sha256'] ?? [])), true),
            'structural' => $this->matchStructural($pattern, $path, $relative, $content, $matched),
            'combo' => $this->matchCombo($pattern, $content, $path.' '.$relative, $matched),
            default => $this->matchSubstring((array)($pattern['any'] ?? $pattern['substring'] ?? []), $content, $matched, (bool)($pattern['case_insensitive'] ?? true)),
        };
        if (!$ok) return null;
        return ['signature'=>$sig,'matched'=>$matched,'risk_explanation'=>$sig['description'] ?? 'Matched malware signature indicators.'];
    }

    private function targets(array $sig, string $path, string $rel, array $meta): bool { $exts=json_decode((string)($sig['target_extensions'] ?? '[]'), true) ?: []; if ($exts && !in_array(strtolower((string)($meta['extension'] ?? pathinfo($path, PATHINFO_EXTENSION))), array_map('strtolower',$exts), true)) return false; return true; }
    private function matchSubstring(array $needles, string $content, array &$matched, bool $ci=true): bool { foreach($needles as $n){ $hit=$ci?stripos($content,(string)$n)!==false:str_contains($content,(string)$n); if($hit){$matched[]=['name'=>'substring','pattern'=>(string)$n,'snippet'=>(string)$n]; return true;}} return false; }
    private function matchRegex(string $regex, string $content, array &$matched): bool { if($regex!=='' && @preg_match($regex,$content,$m)){ $matched[]=['name'=>'regex','pattern'=>$regex,'snippet'=>substr($m[0]??'',0,300)]; return true;} return false; }
    private function matchCombo(array $p, string $content, string $pathText, array &$matched): bool { foreach((array)($p['all']??[]) as $n) if(stripos($content,(string)$n)===false) return false; else $matched[]=['name'=>'all','pattern'=>(string)$n,'snippet'=>(string)$n]; foreach((array)($p['regex_all']??[]) as $r) if(!@preg_match($r,$content,$m)) return false; else $matched[]=['name'=>'regex_all','pattern'=>$r,'snippet'=>substr($m[0]??'',0,300)]; if(isset($p['any']) || isset($p['regex_any'])) { $before=count($matched); $okAny = isset($p['any']) && $this->any((array)$p['any'],$content,$matched); $okRegexAny = isset($p['regex_any']) && $this->regexAny((array)$p['regex_any'],$content,$matched); if(!$okAny && !$okRegexAny) return false; } foreach((array)($p['not']??[]) as $n) if(stripos($content,(string)$n)!==false) return false; foreach((array)($p['required_groups']??[]) as $g){ $hits=0; foreach((array)($g['any']??[]) as $n) if(stripos($content,(string)$n)!==false){$hits++;$matched[]=['name'=>'required_group','pattern'=>(string)$n,'snippet'=>(string)$n];} foreach((array)($g['regex_any']??[]) as $r) if(@preg_match($r,$content,$m)){ $hits++; $matched[]=['name'=>'required_group_regex','pattern'=>$r,'snippet'=>substr($m[0]??'',0,300)]; } if($hits < (int)($g['min']??1)) return false; } return true; }
    private function any(array $needles,string $content,array &$matched): bool { foreach($needles as $n) if(stripos($content,(string)$n)!==false){$matched[]=['name'=>'any','pattern'=>(string)$n,'snippet'=>(string)$n]; return true;} return false; }
    private function regexAny(array $regexes,string $content,array &$matched): bool { foreach($regexes as $r) if(@preg_match($r,$content,$m)){ $matched[]=['name'=>'regex_any','pattern'=>$r,'snippet'=>substr($m[0]??'',0,300)]; return true;} return false; }
    private function matchStructural(array $p,string $path,string $rel,string $content,array &$matched): bool { foreach((array)($p['directory_names']??[]) as $d) if(preg_match('#(^|/)'.preg_quote($d,'#').'(/|$)#i',$rel)){ $matched[]=['name'=>'directory','pattern'=>$d,'snippet'=>$rel]; return true; } foreach((array)($p['path_contains']??[]) as $d) if(stripos($rel,(string)$d)!==false){ $matched[]=['name'=>'path','pattern'=>(string)$d,'snippet'=>$rel]; return true; } return $this->regexAny((array)($p['regex_any']??[]),$content,$matched); }
}
