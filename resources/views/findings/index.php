<?php ob_start(); ?><h1><?= e(t('Findings')) ?></h1>
<form><input class="input" name="path" placeholder="<?= e(t('Path contains')) ?>" value="<?= e($_GET['path']??'') ?>"> <input class="input" name="user" list="userlist" placeholder="<?= e(t('User')) ?>" value="<?= e($_GET['user']??'') ?>"> <datalist id="userlist"><?php foreach($user_names as $un): ?><option value="<?= e($un) ?>"><?php endforeach ?></datalist> <input class="input" name="site" placeholder="<?= e(t('Site')) ?>" value="<?= e($_GET['site']??'') ?>"> <select class="input" name="risk"><option value=""><?= e(t('Any risk')) ?></option><?php foreach(['low','medium','high','critical'] as $r): ?><option value="<?= e($r) ?>" <?= ($_GET['risk']??'')===$r?'selected':'' ?>><?= e(t($r)) ?></option><?php endforeach ?></select> <select class="input" name="status"><option value=""><?= e(t('Any status')) ?></option><?php foreach(['new','ignored','quarantined'] as $r): ?><option value="<?= e($r) ?>" <?= ($_GET['status']??'')===$r?'selected':'' ?>><?= e(t($r)) ?></option><?php endforeach ?></select> <input class="input" type="date" name="date_from" value="<?= e($_GET['date_from']??'') ?>"> <input class="input" type="date" name="date_to" value="<?= e($_GET['date_to']??'') ?>"> <button class="btn"><?= e(t('Filter')) ?></button> <a class="btn" href="/findings/export.csv?<?= e(http_build_query($_GET)) ?>"><?= e(t('Export CSV')) ?></a> <a class="btn" href="/findings/export.json?<?= e(http_build_query($_GET)) ?>"><?= e(t('Export JSON (for AI analysis)')) ?></a></form>
<?php if(isset($_GET['bulk_result'])): $bok=(int)($_GET['bulk_ok']??0); $bfail=(int)($_GET['bulk_fail']??0); ?><div class="card"><p><?= e(t($_GET['bulk_result']==='delete' ? 'Deleted: :ok, failed: :fail' : 'Quarantined: :ok, failed: :fail', ['ok'=>$bok,'fail'=>$bfail])) ?></p></div><?php endif ?>
<?php if(config('guard.web_actions_enabled')): ?>
<form method="post" id="bulkForm" onsubmit="return confirmBulk(event)">
<?php foreach(['risk','status','type','user','site','path','date_from','date_to'] as $bk): ?><input type="hidden" name="back_query[<?= e($bk) ?>]" value="<?= e($_GET[$bk] ?? '') ?>"><?php endforeach ?>
<input type="hidden" name="select_all_filtered" id="selectAllFilteredInput" value="0">
<div class="card actions">
<?php if($total > count($findings)): ?><label><input type="checkbox" id="selectAllFilteredCheckbox" onchange="toggleSelectAllFiltered(this)"> <?= e(t('Select all :n matching current filter', ['n'=>$total])) ?></label><?php endif ?>
<button type="submit" formaction="/findings/bulk-quarantine" class="btn danger"><?= e(t('Quarantine selected')) ?></button>
<button type="submit" formaction="/findings/bulk-delete" class="btn danger"><?= e(t('Delete selected')) ?></button>
</div>
<table><tr><th><input type="checkbox" onchange="toggleAllRows(this)"></th><th><?= e(t('Risk')) ?></th><th><?= e(t('Type')) ?></th><th><?= e(t('User')) ?></th><th><?= e(t('Site')) ?></th><th><?= e(t('Path')) ?></th><th><?= e(t('Matched rules')) ?></th><th><?= e(t('First seen')) ?></th><th><?= e(t('Last seen')) ?></th><th><?= e(t('Status')) ?></th><th><?= e(t('Actions')) ?></th></tr><?php foreach($findings as $f): ?><tr><td><input type="checkbox" class="rowcheck" name="ids[]" value="<?= e($f['id']) ?>"></td><td><span class="badge <?= e($f['risk']) ?>"><?= e(t($f['risk'])) ?></span></td><td><?= e($f['type']) ?></td><td><?= e($f['user_name'] ?? '') ?></td><td><?= e($f['site_name'] ?? '') ?></td><td><code><?= e($f['path']) ?></code></td><td><?= e(mb_strimwidth($f['matched_rules'] ?? '',0,90,'…')) ?></td><td><?= e($f['first_seen_at']) ?></td><td><?= e($f['last_seen_at']) ?></td><td><?= e(t($f['status'])) ?></td><td><a href="/findings/<?= e($f['id']) ?>"><?= e(t('view')) ?></a></td></tr><?php endforeach ?></table>
</form>
<script>
function toggleAllRows(cb){document.querySelectorAll('.rowcheck').forEach(function(c){c.checked=cb.checked;});}
function toggleSelectAllFiltered(cb){document.getElementById('selectAllFilteredInput').value=cb.checked?'1':'0';document.querySelectorAll('.rowcheck').forEach(function(c){c.checked=cb.checked;c.disabled=cb.checked;});}
function confirmBulk(e){
  var selectAll=document.getElementById('selectAllFilteredInput').value==='1';
  var n=selectAll?<?= (int)$total ?>:document.querySelectorAll('.rowcheck:checked').length;
  if(n===0){alert(<?= e(json_encode(t('Nothing selected.'))) ?>);return false;}
  var isDelete=e.submitter&&e.submitter.formAction.indexOf('bulk-delete')!==-1;
  var tpl=isDelete?<?= e(json_encode(t('PERMANENTLY delete :n file(s)? This cannot be undone.'))) ?>:<?= e(json_encode(t('Move :n file(s) to quarantine?'))) ?>;
  return confirm(tpl.replace(':n', n));
}
</script>
<?php else: ?>
<p class="muted"><?= e(t('Web actions disabled. Use CLI:')) ?> <code>php artisan guard:quarantine &lt;finding_id&gt;</code></p>
<table><tr><th><?= e(t('Risk')) ?></th><th><?= e(t('Type')) ?></th><th><?= e(t('User')) ?></th><th><?= e(t('Site')) ?></th><th><?= e(t('Path')) ?></th><th><?= e(t('Matched rules')) ?></th><th><?= e(t('First seen')) ?></th><th><?= e(t('Last seen')) ?></th><th><?= e(t('Status')) ?></th><th><?= e(t('Actions')) ?></th></tr><?php foreach($findings as $f): ?><tr><td><span class="badge <?= e($f['risk']) ?>"><?= e(t($f['risk'])) ?></span></td><td><?= e($f['type']) ?></td><td><?= e($f['user_name'] ?? '') ?></td><td><?= e($f['site_name'] ?? '') ?></td><td><code><?= e($f['path']) ?></code></td><td><?= e(mb_strimwidth($f['matched_rules'] ?? '',0,90,'…')) ?></td><td><?= e($f['first_seen_at']) ?></td><td><?= e($f['last_seen_at']) ?></td><td><?= e(t($f['status'])) ?></td><td><a href="/findings/<?= e($f['id']) ?>"><?= e(t('view')) ?></a></td></tr><?php endforeach ?></table>
<?php endif ?>
<?php $content=ob_get_clean(); include base_path('resources/views/layouts/app.php'); ?>
