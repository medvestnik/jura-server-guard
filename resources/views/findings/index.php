<?php ob_start(); $actionsEnabled=config('guard.web_actions_enabled'); ?>
<h1><?= e(t('Findings')) ?></h1>
<form method="get" action="/findings" class="filter-form">
  <input type="hidden" name="per_page" value="<?= e($_GET['per_page']??config('guard.pagination_default','50')) ?>">
  <input class="input" name="path" placeholder="<?= e(t('Path contains')) ?>" value="<?= e($_GET['path']??'') ?>">
  <input class="input" name="user" list="userlist" placeholder="<?= e(t('User contains')) ?>" value="<?= e($_GET['user']??'') ?>">
  <datalist id="userlist"><?php foreach($user_names as $un): ?><option value="<?= e($un) ?>"><?php endforeach ?></datalist>
  <input class="input" name="site" placeholder="<?= e(t('Site contains')) ?>" value="<?= e($_GET['site']??'') ?>">
  <select class="input" name="type"><option value=""><?= e(t('Any type')) ?></option><?php foreach($types as $type): ?><option value="<?= e($type) ?>" <?= ($_GET['type']??'')===$type?'selected':'' ?>><?= e($type) ?></option><?php endforeach ?></select>
  <select class="input" name="risk"><option value=""><?= e(t('Any risk')) ?></option><?php foreach(['low','medium','high','critical'] as $r): ?><option value="<?= e($r) ?>" <?= ($_GET['risk']??'')===$r?'selected':'' ?>><?= e(t($r)) ?></option><?php endforeach ?></select>
  <select class="input" name="status"><option value=""><?= e(t('Any status')) ?></option><?php foreach(['new','ignored','quarantined','deleted','restored'] as $r): ?><option value="<?= e($r) ?>" <?= ($_GET['status']??'')===$r?'selected':'' ?>><?= e(t($r)) ?></option><?php endforeach ?></select>
  <input class="input" type="date" name="date_from" value="<?= e($_GET['date_from']??'') ?>" title="<?= e(t('Date from')) ?>">
  <input class="input" type="date" name="date_to" value="<?= e($_GET['date_to']??'') ?>" title="<?= e(t('Date to')) ?>">
  <button class="btn"><?= e(t('Filter')) ?></button>
  <a class="btn secondary" href="/findings"><?= e(t('Reset')) ?></a>
  <a class="btn" href="/findings/export.csv?<?= e(http_build_query($_GET)) ?>"><?= e(t('Export CSV')) ?></a>
  <a class="btn" href="/findings/export.json?<?= e(http_build_query($_GET)) ?>"><?= e(t('Export JSON (for AI analysis)')) ?></a>
</form>
<?php
$pageUrl = static function(int $page) use ($pagination): string {
    $query=$_GET; $query['page']=$page; $query['per_page']=$pagination['per_page'];
    return '/findings?'.http_build_query($query);
};
?>
<div class="pagination-bar">
  <span class="pagination-summary"><?= e(t('Showing :from–:to of :count', ['from'=>$pagination['from'],'to'=>$pagination['to'],'count'=>$total])) ?></span>
  <form method="get" action="/findings" class="actions">
    <?php foreach(['risk','status','type','user','site','path','date_from','date_to'] as $pk): if(($_GET[$pk]??'')!==''): ?><input type="hidden" name="<?= e($pk) ?>" value="<?= e($_GET[$pk]) ?>"><?php endif; endforeach ?>
    <label><?= e(t('Records per page')) ?>
      <select class="input" name="per_page" onchange="this.form.submit()">
        <?php foreach($pagination['options'] as $option): ?><option value="<?= e($option) ?>" <?= $pagination['per_page']===$option?'selected':'' ?>><?= e($option==='all'?t('All'):$option) ?></option><?php endforeach ?>
      </select>
    </label>
  </form>
</div>
<?php $bulkJobId=(string)($_GET['bulk_job']??''); if(preg_match('/^[a-f0-9]{32}$/',$bulkJobId)): ?>
  <div class="notice info" id="bulkProgress" data-job="<?= e($bulkJobId) ?>">
    <strong id="bulkProgressTitle"><?= e(t('Bulk action queued…')) ?></strong>
    <div class="progress"><div id="bulkProgressBar" style="width:0%"></div></div>
    <div id="bulkProgressCounts" class="muted"><?= e(t('Processed: :processed of :total; successful: :ok; failed: :fail', ['processed'=>0,'total'=>0,'ok'=>0,'fail'=>0])) ?></div>
    <div id="bulkProgressPath" class="muted"></div>
  </div>
<?php endif ?>
<?php if(isset($_GET['bulk_result']) && ((int)($_GET['bulk_ok']??0)+(int)($_GET['bulk_fail']??0)>0)): $bok=(int)$_GET['bulk_ok']; $bfail=(int)$_GET['bulk_fail']; ?><div class="notice <?= $bfail?'warning':'success' ?>"><?= e(t($_GET['bulk_result']==='delete' ? 'Deleted: :ok, failed: :fail' : 'Quarantined: :ok, failed: :fail', ['ok'=>$bok,'fail'=>$bfail])) ?></div><?php endif ?>
<?php if(isset($_GET['bulk_start_error'])): ?><div class="notice danger-notice"><?= e(t('Bulk action could not be started:')) ?> <?= e($_GET['bulk_start_error']) ?></div><?php endif ?>
<?php if(isset($_GET['quarantined'])): ?><div class="notice success"><?= e(t('File moved to quarantine.')) ?></div><?php endif ?>
<?php if(isset($_GET['deleted'])): ?><div class="notice success"><?= e(t('File permanently deleted from the server.')) ?></div><?php endif ?>
<?php if(isset($_GET['delete_error'])): ?><div class="notice danger-notice"><?= e(t('File could not be deleted:')) ?> <?= e($_GET['delete_error']) ?></div><?php endif ?>

<form method="post" id="bulkForm" autocomplete="off" onsubmit="return confirmBulk(event)">
  <?php foreach(['risk','status','type','user','site','path','date_from','date_to','page','per_page'] as $bk): ?><input type="hidden" name="back_query[<?= e($bk) ?>]" value="<?= e($_GET[$bk] ?? '') ?>"><?php endforeach ?>
  <input type="hidden" name="select_all_filtered" id="selectAllFilteredInput" value="0">
  <?php if($actionsEnabled): ?><div class="card actions">
    <?php if($total > count($findings)): ?><label><input type="checkbox" id="selectAllFilteredCheckbox"> <?= e(t('Select all :n matching current filter', ['n'=>$total])) ?></label><?php endif ?>
    <button type="submit" formaction="/findings/bulk-quarantine" class="btn danger"><?= e(t('Quarantine selected')) ?></button>
    <button type="submit" formaction="/findings/bulk-delete" class="btn danger"><?= e(t('Delete selected')) ?></button>
  </div><?php endif ?>
  <table>
    <tr><?php if($actionsEnabled): ?><th data-no-sort><input type="checkbox" id="selectAllVisibleCheckbox" aria-label="<?= e(t('Select all')) ?>"></th><?php endif ?><th><?= e(t('Risk')) ?></th><th><?= e(t('Type')) ?></th><th><?= e(t('User')) ?></th><th><?= e(t('Site')) ?></th><th><?= e(t('Path')) ?></th><th><?= e(t('Matched rules')) ?></th><th><?= e(t('First seen')) ?></th><th><?= e(t('Last seen')) ?></th><th><?= e(t('Status')) ?></th><th data-no-sort><?= e(t('Actions')) ?></th></tr>
    <?php foreach($findings as $f): ?><tr>
      <?php if($actionsEnabled): ?><td><input type="checkbox" class="rowcheck" name="ids[]" value="<?= e($f['id']) ?>"></td><?php endif ?>
      <td><span class="badge <?= e($f['risk']) ?>"><?= e(t($f['risk'])) ?></span></td><td><?= e($f['type']) ?></td><td><?= e($f['user_name'] ?? '') ?></td><td><?= e($f['site_name'] ?? '') ?></td><td><code><?= e($f['path']) ?></code></td><td><?= e(mb_strimwidth($f['matched_rules'] ?? '',0,90,'…')) ?></td><td><?= e($f['first_seen_at']) ?></td><td><?= e($f['last_seen_at']) ?></td><td><?= e(t($f['status'])) ?></td>
      <td class="actions-cell"><a class="btn small" href="/findings/<?= e($f['id']) ?>#file-content"><?= e(t('View content')) ?></a><?php if($actionsEnabled && !in_array($f['status'],['quarantined','deleted'],true)): ?> <button class="btn danger small" type="submit" formaction="/finding/quarantine" name="id" value="<?= e($f['id']) ?>" onclick="event.stopPropagation();return confirm(<?= e(json_encode(t('Move file to quarantine?'))) ?>)"><?= e(t('Quarantine')) ?></button><input type="hidden" name="return_to" value="findings"><?php endif ?><?php if($actionsEnabled && $f['status']!=='deleted'): ?> <button class="btn danger small" type="submit" formaction="/finding/delete" name="id" value="<?= e($f['id']) ?>" onclick="event.stopPropagation();return confirm(<?= e(json_encode(t('PERMANENTLY delete this file from the server? It cannot be restored.'))) ?>)"><?= e(t('Delete from server')) ?></button><?php endif ?></td>
    </tr><?php endforeach ?>
  </table>
  <?php if($pagination['total_pages']>1): $start=max(1,$pagination['page']-2); $end=min($pagination['total_pages'],$pagination['page']+2); ?>
    <nav class="pagination-bar pagination-pages" aria-label="<?= e(t('Pagination')) ?>">
      <?php if($pagination['page']>1): ?><a class="btn secondary" href="<?= e($pageUrl(1)) ?>"><?= e(t('First')) ?></a><a class="btn secondary" href="<?= e($pageUrl($pagination['page']-1)) ?>"><?= e(t('Previous')) ?></a><?php endif ?>
      <?php for($page=$start;$page<=$end;$page++): ?><a class="btn <?= $page===$pagination['page']?'current':'secondary' ?>" href="<?= e($pageUrl($page)) ?>"><?= e($page) ?></a><?php endfor ?>
      <span class="pagination-summary"><?= e(t('Page :current of :total', ['current'=>$pagination['page'],'total'=>$pagination['total_pages']])) ?></span>
      <?php if($pagination['page']<$pagination['total_pages']): ?><a class="btn secondary" href="<?= e($pageUrl($pagination['page']+1)) ?>"><?= e(t('Next')) ?></a><a class="btn secondary" href="<?= e($pageUrl($pagination['total_pages'])) ?>"><?= e(t('Last')) ?></a><?php endif ?>
    </nav>
  <?php endif ?>
</form>
<?php if(!$actionsEnabled): ?><p class="muted"><?= e(t('Web actions disabled. Use CLI:')) ?> <code>php artisan guard:quarantine &lt;finding_id&gt;</code></p><?php endif ?>
<script>
var bulkForm=document.getElementById('bulkForm');
var visibleAll=document.getElementById('selectAllVisibleCheckbox');
var filteredAll=document.getElementById('selectAllFilteredCheckbox');
var filteredInput=document.getElementById('selectAllFilteredInput');
function rowChecks(){return Array.from(bulkForm.querySelectorAll('.rowcheck'));}
function syncVisibleAll(){
  if(!visibleAll)return;
  var rows=rowChecks(),checked=rows.filter(function(c){return c.checked;}).length;
  visibleAll.checked=rows.length>0&&checked===rows.length;
  visibleAll.indeterminate=checked>0&&checked<rows.length;
}
function toggleAllRows(checked){
  if(filteredAll)filteredAll.checked=false;
  filteredInput.value='0';
  rowChecks().forEach(function(c){c.disabled=false;c.checked=checked;});
  syncVisibleAll();
}
function toggleSelectAllFiltered(checked){
  filteredInput.value=checked?'1':'0';
  rowChecks().forEach(function(c){c.checked=checked;c.disabled=checked;});
  if(visibleAll){visibleAll.checked=checked;visibleAll.indeterminate=false;}
}
if(visibleAll)visibleAll.addEventListener('change',function(){toggleAllRows(this.checked);});
if(filteredAll)filteredAll.addEventListener('change',function(){toggleSelectAllFiltered(this.checked);});
rowChecks().forEach(function(c){c.addEventListener('change',syncVisibleAll);});
// Browsers may restore only the header checkbox after a filtered navigation. Always start from
// a consistent state so a checked "all" box can never submit an empty selection.
filteredInput.value='0';
if(filteredAll)filteredAll.checked=false;
if(visibleAll){visibleAll.checked=false;visibleAll.indeterminate=false;}
rowChecks().forEach(function(c){c.checked=false;c.disabled=false;});
function confirmBulk(e){
  if(e.submitter && (e.submitter.formAction.indexOf('/finding/quarantine')!==-1 || e.submitter.formAction.indexOf('/finding/delete')!==-1)) return true;
  var selectAll=document.getElementById('selectAllFilteredInput').value==='1';
  var n=selectAll?<?= (int)$total ?>:document.querySelectorAll('.rowcheck:checked').length;
  if(n===0){alert(<?= json_encode(t('Nothing selected.'), JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>);return false;}
  var isDelete=e.submitter&&e.submitter.formAction.indexOf('bulk-delete')!==-1;
  var tpl=isDelete?<?= json_encode(t('PERMANENTLY delete :n file(s)? This cannot be undone.'), JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>:<?= json_encode(t('Move :n file(s) to quarantine?'), JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>;
  return confirm(tpl.replace(':n', n));
}
var bulkProgress=document.getElementById('bulkProgress');
if(bulkProgress){
  var bulkLabels={
    delete:<?= json_encode(t('Bulk deletion'), JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>,
    quarantine:<?= json_encode(t('Bulk quarantine'), JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>,
    queued:<?= json_encode(t('queued'), JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>,
    running:<?= json_encode(t('running'), JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>,
    completed:<?= json_encode(t('completed'), JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>,
    failed:<?= json_encode(t('failed'), JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>
  };
  var countTemplate=<?= json_encode(t('Processed: :processed of :total; successful: :ok; failed: :fail'), JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>;
  function renderBulkProgress(state){
    var total=Number(state.total||0),processed=Number(state.processed||0),ok=Number(state.ok||0),fail=Number(state.fail||0);
    var percent=total>0?Math.min(100,Math.round(processed*100/total)):0;
    document.getElementById('bulkProgressBar').style.width=percent+'%';
    document.getElementById('bulkProgressTitle').textContent=(bulkLabels[state.action]||<?= json_encode(t('Bulk action'), JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>)+' — '+(bulkLabels[state.status]||state.status||'');
    document.getElementById('bulkProgressCounts').textContent=countTemplate.replace(':processed',processed).replace(':total',total).replace(':ok',ok).replace(':fail',fail);
    document.getElementById('bulkProgressPath').textContent=state.current_path||state.error||'';
    if(state.status==='completed')bulkProgress.className='notice '+(fail?'warning':'success');
    if(state.status==='failed')bulkProgress.className='notice danger-notice';
    return state.status==='queued'||state.status==='running';
  }
  function pollBulkProgress(){
    fetch('/findings/bulk-status?id='+encodeURIComponent(bulkProgress.dataset.job),{cache:'no-store'})
      .then(function(response){return response.json();})
      .then(function(state){if(renderBulkProgress(state))setTimeout(pollBulkProgress,2000);})
      .catch(function(){setTimeout(pollBulkProgress,4000);});
  }
  pollBulkProgress();
}
</script>
<?php $content=ob_get_clean(); include base_path('resources/views/layouts/app.php'); ?>
