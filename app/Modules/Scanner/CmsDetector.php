<?php
namespace App\Modules\Scanner;

class CmsDetector
{
    public function detect(string $root): array
    {
        $root = rtrim($root, '/');
        $has = fn($p) => file_exists($root.'/'.$p);
        if ($has('wp-includes/version.php') || ($has('wp-admin') && $has('wp-content') && $has('wp-includes'))) return $this->result('wordpress', $this->wpVersion($root), 95, 'wp-admin', 'WordPress structure detected');
        if ($has('administrator/manifests/files/joomla.xml') || ($has('configuration.php') && $has('administrator') && $has('components') && $has('modules'))) return $this->result('joomla', $this->joomlaVersion($root), 90, 'administrator', 'Joomla structure detected');
        if ($has('engine/engine.php') || $has('engine/init.php') || ($has('engine') && $has('engine/data') && $has('templates') && $has('uploads') && $has('index.php'))) {
            $confidence = 60;
            foreach (['engine/ajax','engine/classes','engine/data','engine/modules','templates','uploads','index.php','.htaccess'] as $p) if ($has($p)) $confidence += 4;
            $admin = $has('admin.php') ? 'admin.php' : $this->detectDleAdmin($root);
            $version = $this->dleVersion($root);
            $notes = $version ? 'DataLife Engine structure detected' : 'DataLife Engine structure detected, version unknown';
            return $this->result('dle', $version, min(98, $confidence), $admin, $notes);
        }
        if ($has('system/startup.php') || ($has('catalog') && $has('system') && $has('index.php'))) return $this->result('opencart', $this->openCartVersion($root), 85, $has('admin/config.php')?'admin':null, 'OpenCart structure detected'.($this->openCartVersion($root) ? '' : ', version unknown'));
        return $this->result('unknown', null, 0, null, 'No supported CMS structure detected');
    }

    private function result(string $type, ?string $version, int $confidence, ?string $admin, string $notes): array
    { return ['type'=>$type,'version'=>$version,'confidence'=>$confidence,'admin_path'=>$admin,'notes'=>$version ? $notes : $notes]; }

    private function wpVersion(string $root): ?string { $f=$root.'/wp-includes/version.php'; if(is_readable($f) && preg_match('/\$wp_version\s*=\s*[\'\"]([^\'\"]+)/', file_get_contents($f), $m)) return $m[1]; $readme=$root.'/readme.html'; if(is_readable($readme) && preg_match('/Version\s+([0-9][0-9.]+)/i', file_get_contents($readme, false, null, 0, 20000), $m)) return $m[1]; return null; }
    private function joomlaVersion(string $root): ?string { foreach (['/administrator/manifests/files/joomla.xml','/language/en-GB/en-GB.xml'] as $p) { $f=$root.$p; if(is_readable($f) && preg_match('/<version>([^<]+)/i', file_get_contents($f), $m)) return trim($m[1]); } return null; }
    private function openCartVersion(string $root): ?string { foreach (['/index.php','/admin/index.php','/system/startup.php'] as $p) { $f=$root.$p; if(is_readable($f) && preg_match('/(?:VERSION|APPLICATION_VERSION)[\'\"\s,)]{1,10}([0-9][0-9.]+)/i', file_get_contents($f, false, null, 0, 65536), $m)) return $m[1]; } return null; }
    private function dleVersion(string $root): ?string { foreach (['/engine/data/config.php','/engine/data/dbconfig.php','/engine/engine.php','/engine/init.php','/index.php'] as $p) { $f=$root.$p; if(is_readable($f) && preg_match('/(?:DLE_VERSION|version_id|\$config\[[\'\"]version[\'\"]\]|DataLife Engine(?:[^0-9]{0,20}))\s*[=:,\'\" ]+([0-9][0-9.]+)/i', file_get_contents($f, false, null, 0, 131072), $m)) return $m[1]; } return null; }
    private function detectDleAdmin(string $root): ?string { foreach (glob($root.'/*.php') ?: [] as $f) { $c=@file_get_contents($f, false, null, 0, 65536) ?: ''; if (preg_match('/DATALIFEENGINE|engine\/inc|dle_login_hash|member_db/i', $c)) return basename($f); } return null; }
}
