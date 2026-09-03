<?php ob_start(); ?>
<h1><?= e(t('Suspicious logs')) ?></h1>
<form method="get" action="/logs" class="filter-form">
  <input type="hidden" name="per_page" value="<?= e($_GET['per_page']??config('guard.pagination_default','50')) ?>">
  <input class="input" name="ip" placeholder="IP" value="<?= e($_GET['ip']??'') ?>">
  <input class="input log-uri-filter" name="uri" placeholder="<?= e(t('URI contains')) ?>" value="<?= e($_GET['uri']??'') ?>">
  <input class="input" name="site" placeholder="<?= e(t('Site contains')) ?>" value="<?= e($_GET['site']??'') ?>">
  <select class="input" name="risk"><option value=""><?= e(t('Any risk')) ?></option><?php foreach(['low','medium','high','critical'] as $r): ?><option value="<?= e($r) ?>" <?= ($_GET['risk']??'')===$r?'selected':'' ?>><?= e(t($r)) ?></option><?php endforeach ?></select>
  <input class="input" name="type" placeholder="<?= e(t('Type')) ?>" value="<?= e($_GET['type']??'') ?>">
  <input class="input" type="date" name="date_from" value="<?= e($_GET['date_from']??'') ?>" title="<?= e(t('Date from')) ?>">
  <input class="input" type="date" name="date_to" value="<?= e($_GET['date_to']??'') ?>" title="<?= e(t('Date to')) ?>">
  <button class="btn"><?= e(t('Filter')) ?></button>
  <a class="btn secondary" href="/logs"><?= e(t('Reset')) ?></a>
  <a class="btn" href="/logs/export.csv?<?= e(http_build_query($_GET)) ?>"><?= e(t('Export CSV')) ?></a>
</form>
<?php
$pageUrl = static function(int $page) use ($pagination): string {
    $query=$_GET; $query['page']=$page; $query['per_page']=$pagination['per_page'];
    return '/logs?'.http_build_query($query);
};
?>
<div class="pagination-bar">
  <span class="pagination-summary"><?= e(t('Showing :from–:to of :count', ['from'=>$pagination['from'],'to'=>$pagination['to'],'count'=>$total])) ?></span>
  <form method="get" action="/logs" class="actions">
    <?php foreach(['event_id','risk','type','ip','uri','site','date_from','date_to'] as $pk): if(($_GET[$pk]??'')!==''): ?><input type="hidden" name="<?= e($pk) ?>" value="<?= e($_GET[$pk]) ?>"><?php endif; endforeach ?>
    <label><?= e(t('Records per page')) ?> <select class="input" name="per_page" onchange="this.form.submit()"><?php foreach($pagination['options'] as $option): ?><option value="<?= e($option) ?>" <?= $pagination['per_page']===$option?'selected':'' ?>><?= e($option==='all'?t('All'):$option) ?></option><?php endforeach ?></select></label>
  </form>
</div>

<div class="table-scroll"><table class="suspicious-logs-table">
  <colgroup><col class="log-col-meta"><col class="log-col-source"><col class="log-col-type"><col class="log-col-ip"><col class="log-col-request"><col class="log-col-client"><col class="log-col-actions"></colgroup>
  <tr><th><?= e(t('Date / Risk')) ?></th><th><?= e(t('Site / Source log')) ?></th><th><?= e(t('Type')) ?></th><th>IP</th><th><?= e(t('HTTP request')) ?></th><th><?= e(t('Client details')) ?></th><th data-no-sort><?= e(t('Actions')) ?></th></tr>
  <?php $threatIps=$threatIps??[]; foreach($events as $l): $ti=$threatIps[$l['ip']]??null; $rowId='log-'.$l['id']; $detailsId=$rowId.'-details'; $siteLabel=log_event_site_label($l); ?>
  <tr id="<?= e($rowId) ?>">
    <td class="nowrap"><b><?= e($l['created_at']??'') ?></b><br><span class="badge <?= e($l['risk']) ?>"><?= e(t($l['risk'])) ?></span> <span class="muted">HTTP <?= e($l['status_code']??'—') ?></span></td>
    <td><b><?= e($siteLabel) ?></b><?php if(!empty($l['user_name'])): ?><br><span class="muted"><?= e(t('User')) ?>: <?= e($l['user_name']) ?></span><?php endif ?><br><span class="source-log" title="<?= e($l['log_path']??'') ?>"><code><?= e($l['log_path']??'') ?></code><?= isset($l['line_number'])?' : '.e($l['line_number']):'' ?></span></td>
    <td><?= e($l['event_type']) ?></td>
    <td><b class="nowrap"><?= e($l['ip']) ?></b><?php if($ti): ?><br><span class="badge <?= e($ti['risk']) ?>" title="<?= e(t($ti['classification'])) ?>"><?= e(t($ti['classification'])) ?></span><?php endif ?><?php if(config('guard.firewall_actions_enabled')): ?><form method="post" action="/threat-ips/block" class="log-action-form" onsubmit="return confirm(<?= e(json_encode(t('Block this IP in the server firewall?'))) ?>)"><input type="hidden" name="ip" value="<?= e($l['ip']) ?>"><input type="hidden" name="log_event_id" value="<?= e($l['id']) ?>"><input type="hidden" name="classification" value="<?= e($ti['classification']??'scanner') ?>"><input type="hidden" name="risk" value="<?= e($ti['risk']??$l['risk']??'high') ?>"><button class="btn danger small"><?= e(t('Block IP')) ?></button></form><?php endif ?></td>
    <td class="request-cell"><div class="request-meta"><span class="badge low"><?= e($l['method']??'—') ?></span> <span class="muted">HTTP <?= e($l['status_code']??'—') ?></span></div><code class="request-uri" title="<?= e($l['uri']??'') ?>"><?= e($l['uri']??'') ?></code></td>
    <td><b><?= e(t('User agent')) ?></b><div class="muted clamp-text" title="<?= e($l['user_agent']??'') ?>"><?= e($l['user_agent']?:'—') ?></div><b><?= e(t('Referer')) ?></b><div class="muted clamp-text" title="<?= e($l['referer']??'') ?>"><?= e($l['referer']?:'—') ?></div></td>
    <td class="actions-cell"><button class="btn secondary small" type="button" onclick="toggleLogDetails('<?= e($detailsId) ?>')"><?= e(t('Details')) ?></button> <a class="btn small" href="/threat-ips?ip=<?= urlencode($l['ip']) ?>&event_id=<?= e($l['id']) ?>"><?= e(t($ti?'Open IP':'Flag IP')) ?></a><?php if(log_uri_looks_like_file($l['uri']??null)): ?><br><a class="btn small file-action-link" href="/logs/file?event_id=<?= e($l['id']) ?>"><?= e(t('Inspect requested file')) ?></a><?php endif ?></td>
  </tr>
  <tr id="<?= e($detailsId) ?>" class="details-row" style="display:none"><td colspan="7"><div class="details-grid"><div><b><?= e(t('Site:')) ?></b> <?= e($siteLabel) ?></div><div><b><?= e(t('Source log:')) ?></b> <code><?= e($l['log_path']??'') ?></code><?= isset($l['line_number'])?' : '.e($l['line_number']):'' ?></div><div class="wide"><b><?= e(t('URI:')) ?></b> <code><?= e($l['uri']??'') ?></code></div><div class="wide"><b><?= e(t('Raw log line:')) ?></b><pre><?= e($l['raw_line']??'') ?></pre></div></div></td></tr>
  <?php endforeach ?>
</table></div>
<?php if($pagination['total_pages']>1): $start=max(1,$pagination['page']-2); $end=min($pagination['total_pages'],$pagination['page']+2); ?>
<nav class="pagination-bar pagination-pages" aria-label="<?= e(t('Pagination')) ?>">
  <?php if($pagination['page']>1): ?><a class="btn secondary" href="<?= e($pageUrl(1)) ?>"><?= e(t('First')) ?></a><a class="btn secondary" href="<?= e($pageUrl($pagination['page']-1)) ?>"><?= e(t('Previous')) ?></a><?php endif ?>
  <?php for($page=$start;$page<=$end;$page++): ?><a class="btn <?= $page===$pagination['page']?'current':'secondary' ?>" href="<?= e($pageUrl($page)) ?>"><?= e($page) ?></a><?php endfor ?>
  <span class="pagination-summary"><?= e(t('Page :current of :total', ['current'=>$pagination['page'],'total'=>$pagination['total_pages']])) ?></span>
  <?php if($pagination['page']<$pagination['total_pages']): ?><a class="btn secondary" href="<?= e($pageUrl($pagination['page']+1)) ?>"><?= e(t('Next')) ?></a><a class="btn secondary" href="<?= e($pageUrl($pagination['total_pages'])) ?>"><?= e(t('Last')) ?></a><?php endif ?>
</nav>
<?php endif ?>
<script>
function toggleLogDetails(id){var el=document.getElementById(id);if(el)el.style.display=el.style.display==='none'?'table-row':'none';}
(function(){if(location.hash){var row=document.getElementById(location.hash.slice(1));if(row)row.scrollIntoView({block:'center'});}})();
</script>
<?php $content=ob_get_clean(); include base_path('resources/views/layouts/app.php'); ?>
