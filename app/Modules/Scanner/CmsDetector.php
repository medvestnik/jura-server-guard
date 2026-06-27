<?php
namespace App\Modules\Scanner;

class CmsDetector
{
    public function detect(string $root): array
    {
        $has = fn($p) => file_exists(rtrim($root,'/').'/'.$p);
        if ($has('wp-includes/version.php') || ($has('wp-admin') && $has('wp-content') && $has('wp-includes'))) return ['type'=>'wordpress','version'=>$this->wpVersion($root),'confidence'=>95,'admin_path'=>'wp-admin','notes'=>'WordPress structure detected'];
        if ($has('administrator/manifests/files/joomla.xml') || ($has('configuration.php') && $has('administrator') && $has('components') && $has('modules'))) return ['type'=>'joomla','version'=>$this->joomlaVersion($root),'confidence'=>90,'admin_path'=>'administrator','notes'=>'Joomla structure detected'];
        if ($has('system/startup.php') || ($has('catalog') && $has('system') && $has('index.php'))) return ['type'=>'opencart','version'=>null,'confidence'=>85,'admin_path'=>$has('admin/config.php')?'admin':null,'notes'=>'OpenCart structure detected'];
        return ['type'=>'unknown','version'=>null,'confidence'=>0,'admin_path'=>null,'notes'=>'No supported CMS structure detected'];
    }
    private function wpVersion(string $root): ?string { $f=$root.'/wp-includes/version.php'; if(is_readable($f) && preg_match('/\$wp_version\s*=\s*[\'\"]([^\'\"]+)/', file_get_contents($f), $m)) return $m[1]; return null; }
    private function joomlaVersion(string $root): ?string { $f=$root.'/administrator/manifests/files/joomla.xml'; if(is_readable($f) && preg_match('/<version>([^<]+)/i', file_get_contents($f), $m)) return trim($m[1]); return null; }
}
