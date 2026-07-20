<?php ob_start(); ?><h1><?= e(t('Abuse report draft')) ?></h1><p class="muted"><?= e(t('This is a draft only — nothing is sent automatically. Review it, adjust as needed, and send it yourself to the abuse contact below.')) ?></p>
<div class="card"><p><b>IP:</b> <code><?= e($draft['ip']) ?></code></p>
<?php if($draft['rdap_error']): ?><p style="color:#fca5a5"><?= e(t('Could not look up the network/abuse contact automatically:')) ?> <?= e($draft['rdap_error']) ?> <?= e(t('You will need to find the abuse contact yourself (e.g. via your hosting provider or a WHOIS lookup) and fill in the To: field below.')) ?></p>
<?php else: ?><p><b><?= e(t('Network:')) ?></b> <?= e($draft['network_name'] ?? t('unknown')) ?> <?php if($draft['country']): ?>(<?= e($draft['country']) ?>)<?php endif ?></p>
<?php if($draft['to']): ?><p><b><?= e(t('Abuse contact found:')) ?></b> <code><?= e($draft['to']) ?></code></p><?php else: ?><p style="color:#fbbf24"><?= e(t('No abuse contact email was published in the network registration record. You will need to find one yourself (e.g. via your hosting provider or the network operator\'s website) and fill in the To: field below.')) ?></p><?php endif ?>
<?php endif ?>
</div>
<div class="card"><h2><?= e(t('Draft')) ?></h2>
<p><label><?= e(t('To:')) ?><br><input class="input" style="width:100%" value="<?= e($draft['to'] ?? '') ?>" onclick="this.select()" readonly></label></p>
<p><label><?= e(t('Subject:')) ?><br><input class="input" style="width:100%" value="<?= e($draft['subject']) ?>" onclick="this.select()" readonly></label></p>
<p><label><?= e(t('Body:')) ?><br><textarea class="input" style="width:100%" rows="18" onclick="this.select()" readonly><?= e($draft['body']) ?></textarea></label></p>
</div>
<a class="btn" href="/threat-ips"><?= e(t('Back to Threat IPs')) ?></a>
<?php $content=ob_get_clean(); include base_path('resources/views/layouts/app.php'); ?>
