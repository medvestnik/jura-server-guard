# Jura Server Guard signatures feed

Community incidents/signatures repository:
**[medvestnik/jura-server-guard-signatures-feed](https://github.com/medvestnik/jura-server-guard-signatures-feed)**

This is a companion, public repository of anonymized incident reports and the malware
signatures they produced, meant to be shared across every Jura Server Guard installation —
so a webshell family confirmed on one server can be checked for on every other server running
the panel, without each operator having to rediscover it independently.

> `.env.example`'s `JURA_FEED_REPO` and `config/guard.php`'s `feed_repo` already point here by
> default; this file is the user-facing documentation for that setting and the `guard:feed-*`
> commands/`/feed` panel page that consume it.

## 1. Trust model

The panel is deliberately conservative about what a third-party (even a repo run by the same
maintainer) can cause it to do automatically:

- The panel **never** reads the feed repo's default branch. It only ever fetches a specific
  GitHub Release, by tag, found via the GitHub Releases API — pulling `main` directly would mean
  trusting whatever the latest commit happens to be at fetch time, with no fixed, auditable
  version to point at.
- The downloaded release bundle (`feed-bundle-<tag>.tar.gz`) is verified against a `.sha256`
  sidecar asset published alongside it. A checksum mismatch aborts the fetch outright.
- Every incident file's own SHA-256 (recorded in the bundle's `feed.json` manifest) is
  re-verified again before import, independent of the bundle-level checksum.
- **Signatures imported from the feed always land `enabled=false` with
  `review_status='pending_feed_review'`, never live, regardless of what the incident file's own
  `enabled` field says.** An admin must explicitly approve each one — via `guard:signature-enable`
  or the Signatures page — before it can ever produce a finding. This is the safety net for a
  compromised feed release, or simply an over-broad new signature: it cannot silently go critical
  fleet-wide on every installation that updates.

See `app/Modules/Feed/FeedService.php` for the implementation of all of the above.

## 2. Using the feed

Check whether a newer release is available (informational only — downloads/changes nothing):

```bash
php artisan guard:feed-check
```

Fetch and pin a specific release (downloads, checksum-verifies, and lists the incidents it
contains in `feed_incidents` — does **not** import anything into `malware_signatures` yet):

```bash
php artisan guard:feed-update            # updates to whatever guard:feed-check last saw as latest
php artisan guard:feed-update v2026.09.1 # or a specific tag
php artisan guard:feed-update --yes      # skip the confirmation prompt (for cron)
```

List what's known from the currently pinned release:

```bash
php artisan guard:feed-list
```

Bring one incident's signatures into the scanner (always lands disabled/pending review,
regardless of `--dry-run`):

```bash
php artisan guard:feed-import <incident_id> --dry-run
php artisan guard:feed-import <incident_id>
```

Then review and approve what you actually want live:

```bash
php artisan guard:signature-enable <signature_id>
```

The web equivalent is the **Feed** panel page: check for updates, pin/update a release, see
incidents it brought in, import one, and approve pending signatures from the same page.

## 3. Pointing at your own fork

If you'd rather curate your own feed instead of the shared community one — for example, to keep
contributions internal to your own hosting accounts before deciding whether to upstream them —
point `JURA_FEED_REPO` at a fork or your own repository following the same
`jura-server-guard-signatures-feed` release/bundle format:

```env
JURA_FEED_REPO=your-org/your-fork-name
```

## 4. Contributing back

The feed repository's own README documents the release/bundle format
(`feed.json` manifest + `feed-bundle-<tag>.tar.gz` + its `.sha256` sidecar) for anyone preparing
a release for it. See the
[medvestnik/jura-server-guard-signatures-feed](https://github.com/medvestnik/jura-server-guard-signatures-feed)
repository directly for how to submit incidents.
