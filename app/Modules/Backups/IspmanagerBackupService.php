<?php
namespace App\Modules\Backups;

use App\Support\DB;
use RuntimeException;

class IspmanagerBackupService
{
    public function __construct(private ?string $root = null) { $this->root = rtrim($root ?: (string)config('guard.backup_root', '/var/backup'), '/'); }
    public function root(): string { return $this->root; }
    public function detectTools(): array
    {
        $dirs=['/usr/local/mgr5/','/usr/local/mgr5/sbin/','/usr/local/mgr5/bin/']; $tools=[];
        foreach($dirs as $d) if(is_dir($d)) foreach(scandir($d) ?: [] as $f) { $p=$d.$f; if(is_file($p) && is_executable($p) && preg_match('/(backup|mgr|ispmgr|core)/i',$f)) $tools[]=$p; }
        sort($tools); return ['root_exists'=>is_dir($this->root),'mgr5_exists'=>is_dir('/usr/local/mgr5'),'tools'=>$tools];
    }
    public function users(): array { if(!is_dir($this->root)) return []; $out=[]; foreach(scandir($this->root) ?: [] as $n) if($n[0]!=='.' && is_dir($this->root.'/'.$n)) $out[]=$n; sort($out); return $out; }
    public function backups(?string $user=null): array
    {
        $users=$user?[$user]:$this->users(); $out=[];
        foreach($users as $u){ $dir=$this->root.'/'.$u; if(!is_dir($dir)) continue; foreach(scandir($dir) ?: [] as $d){ if($d[0]==='.') continue; $p=$dir.'/'.$d; if(!is_dir($p)) continue; $out[]=['user'=>$u,'date'=>$d,'path'=>$p,'type'=>$this->backupType($p),'info'=>$this->info($p)]; }}
        usort($out, fn($a,$b)=>[$a['user'],$b['date']] <=> [$b['user'],$a['date']]); return $out;
    }
    public function userFromPath(string $path): ?string { return preg_match('#^/var/www/([^/]+)/data/www/#', $path, $m) ? $m[1] : null; }
    public function findFile(string $path, ?string $date=null): array
    {
        $this->assertSafePath($path); $user=$this->userFromPath($path); if(!$user) return [];
        $rel=ltrim(preg_replace('#^/var/www/'.preg_quote($user,'#').'/#','',$path),'/'); $found=[];
        foreach($this->backups($user) as $b){ if($date && $b['date']!==$date) continue; $hit=$this->findInDirectory($b['path'],$rel); if($hit) $found[]=$hit+['user'=>$user,'date'=>$b['date'],'backup_path'=>$b['path'],'backup_type'=>$b['type']]; }
        usort($found, fn($a,$b)=>strcmp($b['date'],$a['date'])); return $found;
    }
    public function preview(string $path, string $date, int $bytes=65536): string { $f=$this->firstFile($path,$date); return @file_get_contents($f['source'], false, null, 0, $bytes) ?: ''; }
    public function diff(string $path, string $date): string
    {
        $cur=is_readable($path)?file($path):[]; $bak=explode("\n", $this->preview($path,$date,1024*1024)); $out=[]; $max=max(count($cur),count($bak));
        for($i=0;$i<$max;$i++){ $a=rtrim($cur[$i]??''); $b=rtrim($bak[$i]??''); if($a!==$b){ $out[]='- '.$a; $out[]='+ '.$b; if(count($out)>400) { $out[]='... diff truncated ...'; break; } } }
        return implode("\n", $out) ?: 'No text differences in preview window.';
    }
    public function restore(string $path, string $date, ?int $adminId=null): int
    {
        $this->assertSafePath($path); $src=$this->firstFile($path,$date); if(is_dir($path)) throw new RuntimeException('Refusing to restore over directory.');
        $prevHash=is_file($path)?hash_file('sha256',$path):null; $prevSize=is_file($path)?filesize($path):0; $q=null;
        if(config('guard.restore_current_file_to_quarantine', true) && is_file($path)){ $q=rtrim((string)config('guard.quarantine_path'),'/').'/restore-'.date('Ymd-His').'-'.basename($path); @mkdir(dirname($q),0700,true); copy($path,$q); }
        copy($src['source'],$path); chmod($path,0644); $user=$this->userFromPath($path); if($user && function_exists('posix_getpwnam') && posix_getpwnam($user)) @chown($path,$user); if($user && function_exists('posix_getgrnam') && posix_getgrnam($user)) @chgrp($path,$user);
        return DB::insert('INSERT INTO restore_actions (admin_user_id,original_path,backup_provider,backup_user,backup_date,backup_source_archive,previous_sha256,restored_sha256,previous_size,restored_size,quarantine_path,created_at,status,error_message) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',[$adminId,$path,'ispmanager',$user,$date,$src['source'],$prevHash,hash_file('sha256',$path),$prevSize,filesize($path),$q,now(),'completed',null]);
    }
    private function firstFile(string $path,string $date): array { $f=$this->findFile($path,$date)[0] ?? null; if(!$f) throw new RuntimeException('File not found in selected backup date.'); return $f; }
    private function assertSafePath(string $path): void { if(str_contains($path,'..') || !preg_match('#^/var/www/[^/]+/data/www/#',$path)) throw new RuntimeException('Unsafe restore path.'); $dir=realpath(dirname($path)); if($dir && !str_starts_with($dir, '/var/www/')) throw new RuntimeException('Symlink target outside /var/www rejected.'); }
    private function backupType(string $dir): string { $txt=strtolower(json_encode($this->info($dir))); if(str_contains($txt,'increment')) return 'incremental'; if(str_contains($txt,'diff')) return 'differential'; $files=scandir($dir)?:[]; if(preg_grep('/part\d+/i',$files)) return 'multipart'; if(str_contains($txt,'full')) return 'full'; return 'unknown'; }
    private function info(string $dir): array { $out=[]; foreach(glob($dir.'/*.info') ?: [] as $f) $out[basename($f)]=@file_get_contents($f) ?: ''; return $out; }
    private function findInDirectory(string $dir,string $rel): ?array { $candidates=[$dir.'/'.$rel,$dir.'/data/'.$rel,$dir.'/files/'.$rel]; foreach($candidates as $c) if(is_file($c)) return ['source'=>$c,'size'=>filesize($c),'mtime'=>gmdate('Y-m-d H:i:s',filemtime($c)),'sha256'=>hash_file('sha256',$c)]; return null; }
}
