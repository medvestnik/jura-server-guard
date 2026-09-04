<?php ob_start(); ?><h1><?= e(t('Signatures feed')) ?></h1>
<p class="muted"><?= e(t('Community incidents/signatures from :repo. The panel only ever fetches a specific, checksum-verified GitHub Release — never the default branch. Everything a release brings lands disabled and pending review; nothing runs live until you approve it below.', ['repo' => $repo])) ?></p>

<?php if ($flash): ?><div class="notice <?= $flash['type']==='success'?'success':($flash['type']==='warning'?'warning':'danger-notice') ?>"><?= e($flash['message']) ?></div><?php endif ?>

<div class="card">
  <div class="details-grid">
    <div><b><?= e(t('Repository')) ?></b><br><code><?= e($repo) ?></code></div>
    <div><b><?= e(t('Pinned release')) ?></b><br><?= $pinnedTag ? '<code>'.e($pinnedTag).'</code>' : '<span class="muted">'.e(t('none yet')).'</span>' ?></div>
    <div><b><?= e(t('Latest known release')) ?></b><br><?= $latestKnownTag ? '<code>'.e($latestKnownTag).'</code>' : '<span class="muted">'.e(t('unknown — check for updates')).'</span>' ?><?php if($latestKnownTag && $latestKnownTag!==$pinnedTag): ?> <span class="badge medium"><?= e(t('update available')) ?></span><?php endif ?></div>
    <div><b><?= e(t('Last checked')) ?></b><br><span class="muted"><?= e($lastCheckedAt ?: t('never')) ?></span></div>
    <div><b><?= e(t('Last fetched')) ?></b><br><span class="muted"><?= e($lastFetchedAt ?: t('never')) ?></span></div>
  </div>
  <p class="actions" style="margin-top:14px">
    <form method="post" action="/feed/check" class="inline-form"><button class="btn secondary"><?= e(t('Check for updates')) ?></button></form>
    <?php if ($latestKnownTag): ?>
    <form method="post" action="/feed/fetch" class="inline-form" onsubmit="return confirm(<?= e(json_encode(t('Fetch and pin :tag? This downloads and checksum-verifies the release but does not enable any signature.', ['tag'=>$latestKnownTag]))) ?>)">
      <input type="hidden" name="tag" value="<?= e($latestKnownTag) ?>">
      <button class="btn"><?= e(t('Update feed to :tag', ['tag' => $latestKnownTag])) ?></button>
    </form>
    <?php endif ?>
  </p>
  <p class="muted" style="margin-top:6px"><?= e(t('“Update feed” only downloads, verifies, and lists what changed. Bringing a specific incident’s signatures into the scanner — still disabled, pending review — is a separate step below.')) ?></p>
</div>

<div class="card">
  <h2><?= e(t('Published incidents')) ?></h2>
  <?php if (!$incidents): ?>
    <p class="muted"><?= e(t('Nothing fetched yet. Check for updates, then update the feed.')) ?></p>
  <?php else: ?>
  <table>
    <tr><th><?= e(t('Severity')) ?></th><th><?= e(t('Title')) ?></th><th><?= e(t('Incident ID')) ?></th><th><?= e(t('Release')) ?></th><th><?= e(t('Signatures')) ?></th><th><?= e(t('Status')) ?></th><th><?= e(t('Actions')) ?></th></tr>
    <?php foreach ($incidents as $i): $slugs = json_decode((string)$i['signature_slugs_json'], true) ?: []; ?>
    <tr>
      <td><span class="badge <?= e($i['severity'] ?: 'medium') ?>"><?= e(t($i['severity'] ?: 'medium')) ?></span></td>
      <td><?= e($i['title']) ?></td>
      <td><code><?= e($i['incident_id']) ?></code></td>
      <td><code><?= e($i['release_tag']) ?></code></td>
      <td class="muted"><?= e(implode(', ', $slugs)) ?></td>
      <td><?= $i['import_status']==='imported' ? '<span class="badge low">'.e(t('imported')).'</span>' : '<span class="muted">'.e(t('not imported')).'</span>' ?></td>
      <td class="actions-cell">
        <?php if ($i['import_status'] !== 'imported'): ?>
        <form method="post" action="/feed/import" class="inline-form"><input type="hidden" name="incident_id" value="<?= e($i['incident_id']) ?>"><input type="hidden" name="dry_run" value="1"><button class="btn small secondary"><?= e(t('Preview import')) ?></button></form>
        <form method="post" action="/feed/import" class="inline-form" onsubmit="return confirm(<?= e(json_encode(t('Import this incident? Signatures land disabled/pending review — nothing goes live yet.'))) ?>)"><input type="hidden" name="incident_id" value="<?= e($i['incident_id']) ?>"><input type="hidden" name="dry_run" value="0"><button class="btn small"><?= e(t('Import')) ?></button></form>
        <?php else: ?>
        <span class="muted small"><?= e($i['imported_at']) ?></span>
        <?php endif ?>
      </td>
    </tr>
    <?php endforeach ?>
  </table>
  <?php endif ?>
</div>

<div class="card">
  <h2><?= e(t('Pending review')) ?></h2>
  <p class="muted"><?= e(t('Signatures imported from the feed, disabled until you approve them here or via guard:signature-enable.')) ?></p>
  <?php if (!$pendingSignatures): ?>
    <p class="muted"><?= e(t('Nothing pending.')) ?></p>
  <?php else: ?>
  <table>
    <tr><th><?= e(t('Name')) ?></th><th><?= e(t('Risk')) ?></th><th><?= e(t('Type')) ?></th><th><?= e(t('Pattern')) ?></th><th><?= e(t('Release')) ?></th><th><?= e(t('Actions')) ?></th></tr>
    <?php foreach ($pendingSignatures as $s): ?>
    <tr>
      <td><a href="/signatures/<?= e($s['id']) ?>"><?= e($s['name']) ?></a></td>
      <td><span class="badge <?= e($s['risk']) ?>"><?= e(t($s['risk'])) ?></span></td>
      <td><?= e($s['type']) ?></td>
      <td><?= e($s['pattern_type']) ?></td>
      <td><code><?= e($s['feed_release_tag']) ?></code></td>
      <td class="actions-cell">
        <form method="post" action="/signatures/toggle" class="inline-form"><input type="hidden" name="id" value="<?= e($s['id']) ?>"><button class="btn small"><?= e(t('Approve & enable')) ?></button></form>
        <form method="post" action="/signatures/delete" class="inline-form" onsubmit="return confirm(<?= e(json_encode(t('Reject and delete this signature?'))) ?>)"><input type="hidden" name="id" value="<?= e($s['id']) ?>"><button class="btn danger small"><?= e(t('Reject')) ?></button></form>
      </td>
    </tr>
    <?php endforeach ?>
  </table>
  <?php endif ?>
</div>
<?php $content=ob_get_clean(); include base_path('resources/views/layouts/app.php'); ?>
