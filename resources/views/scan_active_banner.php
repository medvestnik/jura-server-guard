<?php $ctx = $ctx ?? (function_exists('scan_active_context') ? scan_active_context() : []); $run=$ctx['run']??null; $lock=$ctx['lock']??null; if (($ctx['running']??false)): $stale=(bool)($ctx['stale']??false); $total=(int)($run['total_files_estimated']??0); $files=(int)($run['files_scanned']??0); $pct=$ctx['progress']??null; $started=$run['started_at']??($lock['started_at']??null); $elapsed=$started?format_duration(max(0,time()-strtotime($started))):'n/a'; ?>
<div class="scan-banner <?= $stale?'scan-stale':'scan-running' ?>">
  <div class="scan-banner-head"><strong><?= $stale?e(t('Stale scan detected')):e(t('Scan is running')) ?></strong><span><?= e(t('Scan #:id', ['id'=>$run['id']??'pending'])) ?></span><a class="btn small" href="/scan/active"><?= e(t('View details')) ?></a></div>
  <?php if($pct !== null): ?><div class="progress"><div style="width:<?= e($pct) ?>%"></div></div><?php endif ?>
  <div class="scan-grid">
    <span><b><?= e(t('Profile:')) ?></b> <?= e(t($run['profile']??'starting')) ?></span><span><b><?= e(t('Scope:')) ?></b> <?= e(t($run['scope_type']??'starting')) ?></span><span><b><?= e(t('Target:')) ?></b> <?= e($run['scope_value']??'full') ?></span><span><b>PID:</b> <?= e($ctx['pid']??'n/a') ?></span>
    <span><b><?= e(t('Files scanned:')) ?></b> <?= e($files) ?></span><span><b><?= e(t('Estimated total files:')) ?></b> <?= e($total ?: t('unknown')) ?></span><span><b><?= e(t('Progress:')) ?></b> <?= e($pct !== null ? $pct.'%' : t('unknown')) ?></span><span><b><?= e(t('Skipped media:')) ?></b> <?= e($run['skipped_media']??0) ?></span>
    <span><b><?= e(t('Skipped directories:')) ?></b> <?= e($run['skipped_directories']??0) ?></span><span><b><?= e(t('Findings:')) ?></b> <?= e($run['findings_count']??0) ?></span><span><b><?= e(t('New findings:')) ?></b> <?= e($run['findings_new']??0) ?></span><span><b><?= e(t('Current site:')) ?></b> <?= e($run['current_site']??'n/a') ?></span>
    <span class="wide"><b><?= e(t('Current path:')) ?></b> <code><?= e($run['current_path']??'n/a') ?></code></span><span><b><?= e(t('Started at:')) ?></b> <?= e($started??'n/a') ?></span><span><b><?= e(t('Elapsed time:')) ?></b> <?= e($elapsed) ?></span><span><b><?= e(t('Last heartbeat:')) ?></b> <?= e($run['last_heartbeat_at']??'n/a') ?></span><span><b><?= e(t('Heartbeat age:')) ?></b> <?= e(isset($ctx['heartbeat_age']) ? $ctx['heartbeat_age'].'s' : 'n/a') ?></span>
    <span class="wide"><b><?= e(t('Progress message:')) ?></b> <?= e($run['progress_message']??($lock['command']??t('Starting background scan'))) ?></span>
  </div>
  <p class="auto-refresh"><?= e(t('This page auto-refreshes every 4 seconds while a scan is active.')) ?></p>
  <?php if($stale): ?><form method="post" action="/scan/cleanup-stale" style="display:inline"><button class="btn danger small"><?= e(t('Cleanup stale scan')) ?></button></form> <form method="post" action="/scan/force-unlock" style="display:inline"><button class="btn danger small"><?= e(t('Force unlock')) ?></button></form><?php endif ?>
</div>
<script>setTimeout(()=>location.reload(),4000)</script>
<?php endif ?>
