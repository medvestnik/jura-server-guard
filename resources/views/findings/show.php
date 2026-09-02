<?php ob_start(); ?>
<h1><?= e(t('Finding #:id', ['id'=>$finding['id'] ?? ''])) ?></h1>
<?php if(!$finding): ?>
<p><?= e(t('Not found.')) ?></p>
<?php else: ?>
<div class="card">
  <p><b><?= e(t('Path:')) ?></b> <code><?= e($finding['path']) ?></code></p>
  <p><b><?= e(t('Risk:')) ?></b> <span class="badge <?= e($finding['risk']) ?>"><?= e(t($finding['risk'])) ?></span> <b><?= e(t('Type:')) ?></b> <?= e($finding['type']) ?> <b><?= e(t('Status:')) ?></b> <?= e(t($finding['status'])) ?></p>
  <p><b>SHA256:</b> <code><?= e($finding['sha256']) ?></code></p>
  <p><b><?= e(t('Size:')) ?></b> <?= e($finding['size']) ?> <b>mtime:</b> <?= e($finding['mtime']) ?> <b><?= e(t('owner:')) ?></b> <?= e($finding['owner']) ?> <b><?= e(t('permissions:')) ?></b> <?= e($finding['permissions']) ?></p>
  <div class="actions">
    <a class="btn" href="#file-content"><?= e(t('View content')) ?></a>
    <form method="post" action="/finding/signature-suggest" class="inline-form" onsubmit="return confirm(<?= e(json_encode(t('Snippets/metadata may be sent to the configured AI provider if AI signatures are enabled. Continue?'))) ?>)"><input type="hidden" name="id" value="<?= e($finding['id']) ?>"><button class="btn"><?= e(t('Generate signature with AI')) ?></button></form>
    <form method="post" action="/finding/create-signature" class="inline-form"><input type="hidden" name="id" value="<?= e($finding['id']) ?>"><button class="btn"><?= e(t('Create signature from this finding')) ?></button></form>
    <a class="btn" href="/signatures?file=<?= urlencode($finding['path']) ?>"><?= e(t('Test existing signatures against this file')) ?></a>
    <form method="post" action="/finding/ignore" class="inline-form"><input type="hidden" name="id" value="<?= e($finding['id']) ?>"><button class="btn"><?= e(t('Ignore')) ?></button></form>
    <form method="post" action="/finding/allowlist" class="inline-form"><input type="hidden" name="id" value="<?= e($finding['id']) ?>"><button class="btn"><?= e(t('Allowlist')) ?></button></form>
    <?php if(config('guard.web_actions_enabled') && !in_array($finding['status'],['quarantined','deleted'],true)): ?><form method="post" action="/finding/quarantine" class="inline-form" onsubmit="return confirm(<?= e(json_encode(t('Move file to quarantine?'))) ?>)"><input type="hidden" name="id" value="<?= e($finding['id']) ?>"><button class="btn danger"><?= e(t('Quarantine')) ?></button></form><?php endif ?>
    <?php if(config('guard.web_actions_enabled') && $finding['status']!=='deleted'): ?><form method="post" action="/finding/delete" class="inline-form" onsubmit="return confirm(<?= e(json_encode(t('PERMANENTLY delete this file from the server? It cannot be restored.'))) ?>)"><input type="hidden" name="id" value="<?= e($finding['id']) ?>"><button class="btn danger"><?= e(t('Delete from server')) ?></button></form><?php endif ?>
  </div>
  <?php if(!config('guard.web_actions_enabled')): ?><p class="muted"><?= e(t('Web actions disabled. Use CLI:')) ?> <code>php artisan guard:quarantine <?= e($finding['id']) ?></code></p><?php endif ?>
  <p><a class="btn" href="/backups?path=<?= urlencode($finding['path']) ?>"><?= e(t('Find in backup')) ?></a></p>
</div>

<div class="card file-content-card" id="file-content">
  <h2><?= e(t('File content')) ?></h2>
  <?php $filePreview=$filePreview??['content'=>'','source'=>null,'error'=>t('Preview unavailable or empty.')]; ?>
  <?php if(!empty($filePreview['error'])): ?><div class="notice warning"><?= e(t($filePreview['error'])) ?></div>
  <?php else: ?>
  <p class="muted"><?= e(t('Read from:')) ?> <code><?= e($filePreview['source']) ?></code><?php if(!empty($filePreview['binary'])): ?> — <?= e(t('binary file; hexadecimal preview')) ?><?php endif ?><?php if(!empty($filePreview['truncated'])): ?> — <?= e(t('preview truncated')) ?><?php endif ?></p>
  <pre class="file-content"><?= e($filePreview['content'] !== '' ? $filePreview['content'] : t('The file is empty.')) ?></pre>
  <?php endif ?>
</div>

<div class="card"><h2><?= e(t('Matched signature:')) ?></h2><p><?= e($finding['matched_signature_name'] ?? '') ?> <?= e($finding['last_matched_signature_id'] ?? '') ?> <?= e($finding['matched_signature_source'] ?? '') ?></p><pre><?= e(json_encode(json_decode($finding['signature_match_details'] ?: '{}', true), JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)) ?></pre></div>
<div class="card"><h2><?= e(t('Matched rules')) ?></h2><pre><?= e(json_encode(json_decode($finding['matched_rules'] ?: '[]', true), JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)) ?></pre></div>

<div class="card"><h2><?= e(t('Related log events')) ?></h2><table><tr><th><?= e(t('Risk')) ?></th><th>IP</th><th><?= e(t('URI')) ?></th><th><?= e(t('Raw')) ?></th></tr><?php foreach($events as $l): ?><tr><td><?= e(t($l['risk'])) ?></td><td><?= e($l['ip']) ?></td><td><?= e($l['uri']) ?></td><td><?= e($l['raw_line']) ?></td></tr><?php endforeach ?></table></div>

<div class="card"><h2><?= e(t('Same file elsewhere')) ?></h2>
<?php if(empty($finding['sha256'])): ?><p class="muted"><?= e(t('No SHA256 recorded for this finding; nothing to compare by exact content.')) ?></p>
<?php elseif(empty($elsewhere)): ?><p class="muted"><?= e(t('No other scanned file with this exact SHA256 was found on any site.')) ?></p>
<?php else: ?><table><tr><th><?= e(t('User')) ?></th><th><?= e(t('Site')) ?></th><th><?= e(t('Path')) ?></th><th><?= e(t('Status')) ?></th><th><?= e(t('Last seen')) ?></th></tr><?php foreach($elsewhere as $o): ?><tr><td><?= e($o['user_name'] ?? '') ?></td><td><?= e($o['site_name'] ?? '') ?></td><td><code><?= e($o['path']) ?></code></td><td><?= $o['is_missing'] ? e(t('deleted')) : e(t('present')) ?></td><td><?= e($o['last_seen_at']) ?></td></tr><?php endforeach ?></table><?php endif ?>
</div>

<?php if(!empty($aiSuggestions)): ?><div class="card"><h2><?= e(t('AI signature suggestions')) ?></h2><table><tr><th><?= e(t('Status')) ?></th><th><?= e(t('Name')) ?></th><th><?= e(t('Risk')) ?></th><th><?= e(t('Pattern')) ?></th><th>AI</th><th><?= e(t('Explanation')) ?></th><th data-no-sort><?= e(t('Actions')) ?></th></tr><?php foreach($aiSuggestions as $s): ?><tr><td><?= e(t($s['status'])) ?></td><td><?= e($s['suggested_name']) ?></td><td><?= e(t($s['suggested_risk'])) ?></td><td><?= e($s['suggested_pattern_type']) ?></td><td><?= e($s['ai_provider']) ?> <?= e($s['model']) ?></td><td><?= e(mb_strimwidth($s['explanation'] ?? '',0,140,'…')) ?></td><td><?php if($s['status']==='ready'||$s['status']==='needs_review'): ?><a class="btn small" href="/signatures/create-from-suggestion?id=<?= e($s['id']) ?>"><?= e(t('Create signature')) ?></a><?php endif ?></td></tr><?php endforeach ?></table></div><?php endif ?>
<?php endif ?>
<?php $content=ob_get_clean(); include base_path('resources/views/layouts/app.php'); ?>
