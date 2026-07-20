<?php ob_start(); ?><h1><?= e(t('AI chat')) ?></h1><p class="muted"><?= e(t('Ask about findings, signatures, or IPs. Quarantine, delete, and trust-IP actions always show a confirmation step before anything actually runs.')) ?></p>
<div class="card">
<?php if(!$messages): ?><p class="muted"><?= e(t('No messages yet. Ask something like "find critical webshells on cyberwash.ua".')) ?></p><?php endif ?>
<?php foreach($messages as $m): ?>
<?php if($m['role']==='user'): ?><p style="text-align:right"><span class="badge" style="background:#1d4ed8"><?= e(t('You')) ?></span><br><?= nl2br(e($m['content'])) ?></p>
<?php elseif($m['tool_name']===null): ?><p><span class="badge" style="background:#334155">AI</span><br><?= nl2br(e($m['content'])) ?></p>
<?php elseif($m['tool_status']==='pending'): ?><div class="card" style="border-color:#f59e0b"><p><b><?= e(t('AI wants to run an action:')) ?></b></p><p><code><?= e($m['tool_name']) ?></code> <?= e($m['tool_arguments_json']) ?></p><?php if(!empty($m['content'])): ?><p class="muted"><?= nl2br(e($m['content'])) ?></p><?php endif ?><form method="post" action="/ai-chat/confirm" style="display:inline"><input type="hidden" name="id" value="<?= e($m['id']) ?>"><button class="btn danger" onclick="return confirm(<?= e(json_encode(t('Confirm this action?'))) ?>)"><?= e(t('Confirm')) ?></button></form> <form method="post" action="/ai-chat/cancel" style="display:inline"><input type="hidden" name="id" value="<?= e($m['id']) ?>"><button class="btn"><?= e(t('Cancel')) ?></button></form></div>
<?php elseif($m['tool_status']==='cancelled'): ?><p class="muted"><?= e(t('Action cancelled:')) ?> <code><?= e($m['tool_name']) ?></code> <?= e($m['tool_arguments_json']) ?></p>
<?php else: ?><p class="muted"><?= e(t('Action completed:')) ?> <code><?= e($m['tool_name']) ?></code> — <?= e($m['tool_result']) ?></p>
<?php endif ?>
<?php endforeach ?>
</div>
<form method="post" action="/ai-chat/send" class="card"><textarea class="input" style="width:100%" name="message" rows="3" placeholder="<?= e(t('Type a message…')) ?>" required></textarea><br><br><button class="btn"><?= e(t('Send')) ?></button></form>
<form method="post" action="/ai-chat/clear" onsubmit="return confirm(<?= e(json_encode(t('Clear the whole conversation?'))) ?>)"><button class="btn small"><?= e(t('Clear conversation')) ?></button></form>
<?php $content=ob_get_clean(); include base_path('resources/views/layouts/app.php'); ?>
