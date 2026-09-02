<?php ob_start();
$existingIp = $existingIp ?? null;
$contextEvent = $contextEvent ?? null;
$evidenceByIp = $evidenceByIp ?? [];
?>
<h1><?= e(t('Threat IPs')) ?></h1>
<p class="muted"><?= e(t('Attacker IPs with automatically recorded evidence. Firewall blocking is available when enabled in configuration.')) ?></p>

<?php if ($existingIp): ?>
<div class="notice warning"><?= e(t('This IP is already in the attacker list. Its existing record will be updated.')) ?></div>
<?php elseif ($prefillIp !== ''): ?>
<div class="notice info"><?= e(t('This IP is not yet in the attacker list.')) ?></div>
<?php endif ?>
<?php if (($_GET['saved'] ?? '') === '1'): ?><div class="notice success"><?= e(t('IP and detection context saved.')) ?></div><?php endif ?>
<?php if (($_GET['block_result'] ?? '') === 'blocked'): ?><div class="notice success"><?= e(t('IP blocked in the runtime and permanent firewalld configuration.')) ?></div><?php endif ?>
<?php if (($_GET['block_result'] ?? '') === 'already_blocked'): ?><div class="notice info"><?= e(t('This IP is already blocked by firewalld.')) ?></div><?php endif ?>
<?php if (($_GET['block_result'] ?? '') === 'block_failed'): ?><div class="notice danger-notice"><?= e(t('IP could not be blocked:')) ?> <?= e($_GET['block_message'] ?? '') ?></div><?php endif ?>

<?php if ($contextEvent): ?>
<div class="card evidence-card">
  <h2><?= e(t('Detected request')) ?></h2>
  <div class="details-grid">
    <div><b><?= e(t('Site')) ?>:</b> <?= e($contextEvent['site_name'] ?? t('Unknown')) ?></div>
    <div><b><?= e(t('Detected at')) ?>:</b> <?= e($contextEvent['created_at'] ?? '') ?></div>
    <div class="wide"><b><?= e(t('Requested file / URI')) ?>:</b> <code><?= e($contextEvent['uri'] ?? '') ?></code></div>
    <div class="wide"><b><?= e(t('Log file')) ?>:</b> <code><?= e($contextEvent['log_path'] ?? '') ?></code></div>
  </div>
  <p class="muted"><?= e(t('This evidence will be saved automatically; the comment below is optional.')) ?></p>
</div>
<?php endif ?>

<div class="card">
  <h2><?= e(t('Add / update IP')) ?></h2>
  <form method="post" action="/threat-ips/save">
    <input type="hidden" name="log_event_id" value="<?= e($contextEvent['id'] ?? '') ?>">
    <div class="form-row">
      <input class="input" name="ip" placeholder="1.2.3.4" value="<?= e($prefillIp) ?>" required>
      <select class="input" name="classification"><?php foreach($classifications as $c): ?><option value="<?= e($c) ?>" <?= ($existingIp['classification'] ?? '')===$c?'selected':'' ?>><?= e(t($c)) ?></option><?php endforeach ?></select>
      <select class="input" name="risk"><?php foreach(['low','medium','high','critical'] as $r): ?><option value="<?= e($r) ?>" <?= ($existingIp['risk'] ?? 'medium')===$r?'selected':'' ?>><?= e(t($r)) ?></option><?php endforeach ?></select>
    </div>
    <p><textarea class="input wide-input" name="notes" rows="2" placeholder="<?= e(t('Optional comment')) ?>"></textarea></p>
    <div class="actions">
      <button class="btn"><?= e(t('Save')) ?></button>
      <?php if ($prefillIp !== ''): ?><button class="btn danger" type="submit" formaction="/threat-ips/block" formmethod="post" onclick="return confirm(<?= e(json_encode(t('Block this IP in firewalld?'))) ?>)"><?= e(t('Block IP')) ?></button><?php endif ?>
    </div>
  </form>
  <?php if (!config('guard.firewall_actions_enabled')): ?><p class="muted"><?= e(t('Firewall actions are disabled. Enable JURA_FIREWALL_ACTIONS_ENABLED=true to use blocking buttons.')) ?></p><?php endif ?>
</div>

<table>
  <tr><th>IP</th><th><?= e(t('Classification')) ?></th><th><?= e(t('Risk')) ?></th><th><?= e(t('Evidence')) ?></th><th><?= e(t('Notes')) ?></th><th><?= e(t('Hits')) ?></th><th><?= e(t('First seen')) ?></th><th><?= e(t('Last seen')) ?></th><th><?= e(t('Firewall')) ?></th><th data-no-sort><?= e(t('Actions')) ?></th></tr>
  <?php foreach($ips as $i): $evidence=$evidenceByIp[(int)$i['id']]??[]; ?>
  <tr>
    <td><code><?= e($i['ip']) ?></code></td><td><?= e(t($i['classification'])) ?></td><td><span class="badge <?= e($i['risk']) ?>"><?= e(t($i['risk'])) ?></span></td>
    <td><?php if(!$evidence): ?><span class="muted">—</span><?php else: foreach(array_slice($evidence,0,3) as $ev): ?><div class="evidence-item"><b><?= e($ev['site_name'] ?: t('Unknown site')) ?></b><br><code><?= e($ev['file_path'] ?: $ev['request_uri']) ?></code><br><span class="muted"><?= e($ev['detected_at']) ?></span></div><?php endforeach; if(count($evidence)>3): ?><span class="muted">+<?= count($evidence)-3 ?></span><?php endif; endif ?></td>
    <td><?= e($i['notes']) ?></td><td><?= e($i['hit_count']) ?></td><td><?= e($i['first_seen_at']) ?></td><td><?= e($i['last_seen_at']) ?></td>
    <td><?php if(($i['firewall_status']??'')==='blocked'): ?><span class="badge low"><?= e(t('Blocked')) ?></span><br><span class="muted"><?= e($i['blocked_at']??'') ?></span><?php elseif(($i['firewall_status']??'')==='failed'): ?><span class="badge critical" title="<?= e($i['firewall_error']??'') ?>"><?= e(t('Error')) ?></span><?php else: ?><span class="muted"><?= e(t('Not blocked')) ?></span><?php endif ?></td>
    <td class="actions-cell">
      <a class="btn small" href="/logs?ip=<?= urlencode($i['ip']) ?>"><?= e(t('View logs')) ?></a>
      <a class="btn small" href="/threat-ips/abuse-report?ip=<?= urlencode($i['ip']) ?>"><?= e(t('Abuse report')) ?></a>
      <?php if(($i['firewall_status']??'')!=='blocked'): ?><form method="post" action="/threat-ips/block" class="inline-form" onsubmit="return confirm(<?= e(json_encode(t('Block this IP in firewalld?'))) ?>)"><input type="hidden" name="ip" value="<?= e($i['ip']) ?>"><button class="btn danger small"><?= e(t('Block')) ?></button></form><?php else: ?><span class="badge low"><?= e(t('Already blocked')) ?></span><?php endif ?>
      <?php if(($i['firewall_status']??'')!=='blocked'): ?><form method="post" action="/threat-ips/delete" class="inline-form" onsubmit="return confirm(<?= e(json_encode(t('Remove this IP from the list?'))) ?>)"><input type="hidden" name="id" value="<?= e($i['id']) ?>"><button class="btn danger small"><?= e(t('Delete')) ?></button></form><?php endif ?>
    </td>
  </tr>
  <?php endforeach ?>
</table>
<?php $content=ob_get_clean(); include base_path('resources/views/layouts/app.php'); ?>
