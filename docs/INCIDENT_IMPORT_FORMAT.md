# Jura Server Guard incident import format

This document is the **canonical authoring contract** for incident files imported by Jura Server Guard.

> Important: the runtime validator may accept a smaller subset of fields. Do **not** use the validator alone as the authoring specification. Incident files intended for interchange, archival, AI-assisted preparation, or future re-import must follow the canonical profile below and should match the structure of known-good imported incident files.

Format identifier:

```json
{
  "format": "jura-server-guard-incident",
  "format_version": "1.0"
}
```

Only the incident JSON file is imported. A companion Markdown report is for humans and is **not** an import file.

## 1. File requirements

- UTF-8 JSON.
- No comments or trailing commas.
- Recommended filename:
  - `<site>-incident-YYYY-MM-DD.json`, or
  - `<server>-incident-YYYY-MM-DD.json`.
- Use ISO 8601 timestamps with an explicit timezone offset, for example:
  `2026-08-31T10:05:56+03:00`.
- Always include `generated_at`.
- Use stable machine-readable incident IDs and signature slugs. Re-import uses those values for upsert/deduplication.

Recommended top-level order:

```text
format
format_version
generated_at
incident
threat_ips
excluded_ips
malware_signatures
file_iocs
path_indicators
affected_assets
response_actions
data_gaps
import_policy
```

`excluded_ips` and `data_gaps` may be empty or omitted when genuinely not applicable. The other sections should normally be present, even if their arrays are empty.

## 2. Canonical top-level skeleton

```json
{
  "format": "jura-server-guard-incident",
  "format_version": "1.0",
  "generated_at": "2026-08-31T17:00:00+03:00",
  "incident": {},
  "threat_ips": [],
  "excluded_ips": [],
  "malware_signatures": [],
  "file_iocs": [],
  "path_indicators": [],
  "affected_assets": {
    "confirmed_artifacts": [],
    "related_confirmed_activity": [],
    "operator_ip_observed_in_access_logs_not_equal_to_confirmed_compromise": []
  },
  "response_actions": {},
  "data_gaps": [],
  "import_policy": {
    "threat_ip_upsert_key": "ip",
    "signature_upsert_key": "slug",
    "file_ioc_dedup_key": "sha256_when_available_else_name_size_markers",
    "on_conflict": "update_mutable_fields_preserve_first_seen",
    "dry_run_default": true,
    "notes": "Canonical jura-server-guard-incident 1.0 contract."
  }
}
```

## 3. `incident`

Required canonical fields:

- `id` — stable external ID.
- `title` — human-readable title.
- `severity` — one of `low`, `medium`, `high`, `critical`.
- `confidence` — normally `low`, `medium`, or `high`.
- `status` — recommended operational values include `contained_monitoring`, `investigating`, or another stable machine-readable status used by the team.
- `server` — server/site context.
- `timeline` — named event keys with ISO 8601 timestamp values.
- `summary` — concise evidence-based incident summary.

Example:

```json
"incident": {
  "id": "example-2026-08-31-webshell",
  "title": "Confirmed PHP webshell compromise on example.com",
  "severity": "critical",
  "confidence": "high",
  "status": "contained_monitoring",
  "server": {
    "hostname": "data10.jurahost.com",
    "site": "example.com",
    "site_path": "/var/www/example/data/www/example.com",
    "server_user": "example",
    "cms": "Joomla"
  },
  "timeline": {
    "first_known_artifact_at": "2026-08-30T09:46:54+03:00",
    "confirmed_operator_activity_start": "2026-08-30T09:47:16+03:00",
    "cleanup_started_at": "2026-08-31T14:00:00+03:00"
  },
  "summary": "Confirmed webshell activity was observed and contained."
}
```

### Timeline rule

Use **event names as keys** and timestamps as values.

Correct:

```json
"timeline": {
  "webshell_created_at": "2026-08-30T09:46:54+03:00"
}
```

Do not author new files like this:

```json
"timeline": {
  "2026-08-30 09:46:54 +03:00": "webshell created"
}
```

The canonical structure is easier to render, diff, validate, and consume programmatically.

### Initial-access assessment

When the initial vector is uncertain, preserve that uncertainty explicitly instead of guessing:

```json
"initial_access_assessment": {
  "most_likely_vector": "unknown",
  "endpoint": "/conf.php",
  "confidence": "unknown_for_initial_entry_high_for_subsequent_webshell_use",
  "reason": "Older logs were no longer retained, so the first write event cannot be proven."
}
```

## 4. `threat_ips`

Canonical fields:

- `ip`
- `classification`
- `risk`
- `confidence`
- `recommended_action`
- `notes`
- `source`

Optional:

- `hit_count`

Allowed importer classifications:

- `scanner`
- `bruteforce`
- `webshell_access`
- `bot`
- `direct_login`
- `manual`
- `unknown`

Risk values:

- `low`
- `medium`
- `high`
- `critical`

Always use:

```text
source = incident:<incident.id>
```

Example:

```json
{
  "ip": "203.0.113.10",
  "classification": "webshell_access",
  "risk": "critical",
  "confidence": "high",
  "recommended_action": "block",
  "notes": "Confirmed interactive access to the uploaded file manager.",
  "source": "incident:example-2026-08-31-webshell"
}
```

Do not classify an IP as the initial attacker merely because it requested a known shell path. If creation/upload is not proven, use `scanner` or another appropriately conservative classification and explain the limitation in `notes`.

## 5. `excluded_ips`

Use for infrastructure that appears in the incident logs but should **not** be treated as attacker infrastructure solely because of this incident: Google verification, Googlebot, Bingbot, Telegram preview infrastructure, trusted monitoring, and similar services.

Canonical example:

```json
{
  "ip": "192.0.2.20",
  "classification": "bot",
  "reason": "Google Site Verification infrastructure observed after token upload.",
  "recommended_action": "do_not_block_from_this_incident"
}
```

Do not add excluded IPs to `threat_ips`.

## 6. `malware_signatures`

Canonical fields for every signature:

- `name`
- `slug`
- `description`
- `risk`
- `type`
- `pattern_type`
- `pattern_json`
- `target_extensions`
- `target_paths`
- `exclude_paths`
- `required_hits`
- `enabled`
- `source`

Supported `pattern_type` values:

- `hash`
- `combo`
- `regex`
- `substring`
- `structural`

### Exact-hash signature

```json
{
  "name": "Confirmed shell exact hash",
  "slug": "example-shell-sha256",
  "description": "Exact hash of the confirmed incident shell.",
  "risk": "critical",
  "type": "webshell",
  "pattern_type": "hash",
  "pattern_json": {
    "sha256": [
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ]
  },
  "target_extensions": ["php", "phtml", "phar"],
  "target_paths": [],
  "exclude_paths": [],
  "required_hits": 1,
  "enabled": true,
  "source": "incident:example-2026-08-31-webshell"
}
```

### Combo signature

```json
"pattern_type": "combo",
"pattern_json": {
  "all": ["marker-one", "marker-two"],
  "any": ["optional-marker-a", "optional-marker-b"],
  "regex_all": ["/\\beval\\s*\\(/i"],
  "regex_any": ["/goto\\s+[A-Za-z0-9_]+;/i"]
}
```

Use only the keys supported by the signature engine. Prefer several distinctive markers over one generic PHP function.

### Regex signature

```json
"pattern_type": "regex",
"pattern_json": {
  "regex": "#POST\\s+/index\\.php\\?option=com_jce&task=profiles\\.import#i"
}
```

Request/log signatures should normally be `enabled: false` unless the scanner path/content target is appropriate for the rule.

### Structural signature

```json
"pattern_type": "structural",
"pattern_json": {
  "path_regex": "#(^|/)images/wp-news\\.php$#i"
}
```

### Substring signature

```json
"pattern_type": "substring",
"pattern_json": {
  "any": ["distinctive-marker-a", "distinctive-marker-b"],
  "case_insensitive": true
}
```

Avoid broad standalone markers such as common JavaScript/PHP function names. If a marker can occur legitimately, constrain it with a `combo`, path rule, hash, or disable the signature for review-only use.

### Google verification files

Do not create a generic signature for every `google*.html` file. Use exact hashes for incident-confirmed unauthorized tokens and keep broad filename patterns contextual/review-only.

## 7. `file_iocs`

### Hash known

Preferred canonical shape:

```json
{
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "size": 537953,
  "names": ["cache.php", "enc.php", "wp-news.php"],
  "role": "php_file_manager_shell",
  "risk": "critical",
  "confidence": "high",
  "scope": "example.com"
}
```

### Hash unavailable

A missing hash is allowed. Set `sha256` to `null` and identify the artifact by `name` or `names`:

```json
{
  "sha256": null,
  "size": 5571,
  "name": "filefuns.php",
  "path": "/var/www/example/data/www/example.com/filefuns.php",
  "role": "obfuscated_remote_eval_webshell",
  "risk": "critical",
  "confidence": "high",
  "hash_status": "not_captured_in_available_evidence"
}
```

Optional evidence fields such as `path`, `mtime`, `hash_status`, and `content_markers` may be included. They remain useful in the raw incident JSON even if not all of them are promoted to dedicated database columns.

When a SHA-256 is present it must be a 64-character hexadecimal string.

## 8. `path_indicators`

Canonical fields:

- `pattern`
- `kind`
- `risk`
- `confidence`
- `notes` when explanation is useful

Common `kind` values used in incident files:

- `basename`
- `suffix`
- `glob`
- `regex`
- `path_set`
- `request_uri`
- `nested_backdoor_tree`
- `document_root_name_set`

Example:

```json
{
  "pattern": "/assets/images/photos/logo/wp-yahho.php",
  "kind": "suffix",
  "risk": "critical",
  "confidence": "high",
  "notes": "Confirmed no-auth PHP file manager."
}
```

## 9. `affected_assets`

For current panel compatibility, use the established array-based shape even for a single-site incident:

```json
"affected_assets": {
  "confirmed_artifacts": ["example.com"],
  "related_confirmed_activity": [],
  "operator_ip_observed_in_access_logs_not_equal_to_confirmed_compromise": []
}
```

This allows the incident page to resolve site names against the inventory.

Site path, server user, CMS/framework, and similar single-site metadata belong in `incident.server`.

## 10. `response_actions`

Record what was actually done. Prefer machine-readable keys and scalar/array values.

Example:

```json
"response_actions": {
  "evidence_root": "/root/incident-example-20260831",
  "confirmed_malicious_objects_quarantined": 8,
  "malicious_front_controller_quarantined": true,
  "clean_index_restored_from_backup": true,
  "nginx_php_execution_blocks_tested": true,
  "post_cleanup_test_examples": [
    "/shell.php -> HTTP 403",
    "/ru -> HTTP 200"
  ],
  "status": "contained_monitoring"
}
```

Do not claim an action unless it was actually performed and verified.

## 11. `data_gaps`

Use this section to preserve missing evidence and uncertainty instead of silently filling gaps.

Example:

```json
"data_gaps": [
  {
    "field": "initial_access_vector",
    "reason": "Relevant older HTTP logs were no longer retained."
  },
  {
    "field": "webshell_sha256",
    "reason": "The file was removed before its hash was collected.",
    "collection_command": "find /root/incident-* -type f -name 'shell.php*' -print0 | xargs -0 -r sha256sum"
  }
]
```

## 12. `import_policy`

Use this canonical block unless the importer contract changes:

```json
"import_policy": {
  "threat_ip_upsert_key": "ip",
  "signature_upsert_key": "slug",
  "file_ioc_dedup_key": "sha256_when_available_else_name_size_markers",
  "on_conflict": "update_mutable_fields_preserve_first_seen",
  "dry_run_default": true,
  "notes": "Uses the jura-server-guard-incident 1.0 contract."
}
```

Current behavior:

- threat IPs are upserted by `ip`;
- malware signatures are upserted by `slug`;
- file IOCs use SHA-256 when known, otherwise a stable identity derived from name/size/role;
- re-importing an incident with the same `incident.id` updates the existing incident instead of creating a second incident.

## 13. Import procedure

Always run dry-run first:

```bash
cd /opt/jura-server-guard

/opt/php83/bin/php artisan guard:incident-import /root/incident.json --dry-run
```

Review the preview. If it is correct:

```bash
/opt/php83/bin/php artisan guard:incident-import /root/incident.json
/opt/php83/bin/php artisan guard:incident-list
```

The web equivalent is **Incidents → Import incident file**. Dry run should remain enabled for the first upload.

## 14. Pre-import checklist

Before importing a newly authored incident file, verify:

1. `format` is exactly `jura-server-guard-incident`.
2. `format_version` is `1.0`.
3. `generated_at` exists and includes a timezone.
4. `incident.id` is stable and unique.
5. `incident.timeline` uses named keys and ISO timestamp values.
6. Every threat IP has classification, risk, confidence, notes, recommended action, and `source`.
7. Confirmed attacker IPs are separated from scanners/probers and from excluded infrastructure.
8. Every signature has the full canonical signature field set and `source`.
9. Every known SHA-256 is exactly 64 hex characters.
10. A file IOC without SHA-256 has `name` or `names` and a reason/hash status when possible.
11. `affected_assets` uses array values with the established keys.
12. Claims in `response_actions` are evidence-backed.
13. Unknown facts are recorded in `data_gaps`, not guessed.
14. `import_policy` matches the canonical v1 block.
15. The file passes `guard:incident-import ... --dry-run`.

## 15. Canonical example

A copyable complete example is stored at:

`docs/examples/incident-v1.example.json`

When creating an incident manually or with an AI assistant, start from that example and this document rather than inferring the contract from application code alone.
