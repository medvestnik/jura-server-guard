<?php ob_start(); $actionsEnabled=config('guard.web_actions_enabled'); $finding=$fileContext['finding']??null; ?>
<h1 data-pause-auto-refresh><?= e(t('Requested file from log event')) ?></h1>
<?php if(!$event): ?>
  <div class="notice danger-notice"><?= e(t('Log event not found.')) ?></div>
<?php else: ?>
  <div class="card details-grid">
    <div><b><?= e(t('Site:')) ?></b> <?= e(log_event_site_label($event)) ?></div>
    <div><b><?= e(t('IP:')) ?></b> <?= e($event['ip']??'') ?></div>
    <div><b><?= e(t('Timestamp:')) ?></b> <?= e($event['created_at']??'') ?></div>
    <div><b><?= e(t('Source log:')) ?></b> <code><?= e($event['log_path']??'') ?></code><?= isset($event['line_number'])?' : '.e($event['line_number']):'' ?></div>
    <div class="wide"><b><?= e(t('URI:')) ?></b> <code><?= e($event['uri']??'') ?></code></div>
    <?php if(!empty($fileContext['path'])): ?><div class="wide"><b><?= e(t('Resolved server path:')) ?></b> <code><?= e($fileContext['path']) ?></code></div><?php endif ?>
  </div>
  <?php if(isset($_GET['quarantine'])): ?><div class="notice success"><?= e(t('File moved to quarantine.')) ?></div><?php endif ?>
  <?php if(isset($_GET['delete'])): ?><div class="notice success"><?= e(t('File permanently deleted from the server.')) ?></div><?php endif ?>
  <?php if(isset($_GET['action_error'])): ?><div class="notice danger-notice"><?= e(t('Action failed:')) ?> <?= e(t((string)$_GET['action_error'])) ?></div><?php endif ?>
  <?php if(!empty($fileContext['error'])): ?><div class="notice warning"><?= e(t($fileContext['error'])) ?></div>
  <?php elseif(empty($fileContext['exists'])): ?><div class="notice warning"><?= e(t('The file no longer exists at the resolved server path.')) ?><?php if($finding): ?> <?= e(t('Recorded status:')) ?> <b><?= e(t($finding['status'])) ?></b>.<?php endif ?></div>
  <?php endif ?>

  <?php if($finding): ?><p><a class="btn secondary" href="/findings/<?= e($finding['id']) ?>#file-content"><?= e(t('Open finding')) ?> #<?= e($finding['id']) ?></a></p><?php endif ?>
  <?php if(!empty($fileContext['exists']) && $actionsEnabled): ?>
    <div class="card actions">
      <form method="post" action="/logs/file/quarantine" class="inline-form" onsubmit="return confirm(<?= e(json_encode(t('Move file to quarantine?'))) ?>)"><input type="hidden" name="event_id" value="<?= e($event['id']) ?>"><button class="btn danger"><?= e(t('Quarantine')) ?></button></form>
      <form method="post" action="/logs/file/delete" class="inline-form" onsubmit="return confirm(<?= e(json_encode(t('PERMANENTLY delete this file from the server? It cannot be restored.'))) ?>)"><input type="hidden" name="event_id" value="<?= e($event['id']) ?>"><button class="btn danger"><?= e(t('Delete from server')) ?></button></form>
    </div>
  <?php elseif(!empty($fileContext['exists'])): ?><div class="notice warning"><?= e(t('Web actions are disabled by JURA_WEB_ACTIONS_ENABLED.')) ?></div><?php endif ?>

  <div class="card" id="file-content"><h2><?= e(t('File content')) ?></h2>
    <?php if(!empty($filePreview['error'])): ?><div class="notice warning"><?= e(t($filePreview['error'])) ?></div>
    <?php else: ?><p class="muted"><?= e(t('Read from:')) ?> <code><?= e($filePreview['source']) ?></code><?php if(!empty($filePreview['binary'])): ?> — <?= e(t('binary file; hexadecimal preview')) ?><?php endif ?><?php if(!empty($filePreview['truncated'])): ?> — <?= e(t('preview truncated')) ?><?php endif ?></p><pre class="file-content"><?= e($filePreview['content']!==''?$filePreview['content']:t('The file is empty.')) ?></pre><?php endif ?>
  </div>
  <div class="card"><h2><?= e(t('Raw log line:')) ?></h2><pre><?= e($event['raw_line']??'') ?></pre></div>
<?php endif ?>
<p><a class="btn secondary" href="/logs?event_id=<?= e((int)($event['id']??0)) ?>#log-<?= e((int)($event['id']??0)) ?>"><?= e(t('Back to log event')) ?></a></p>
<?php $content=ob_get_clean(); include base_path('resources/views/layouts/app.php'); ?>
