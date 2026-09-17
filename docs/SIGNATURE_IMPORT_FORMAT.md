# Jura Server Guard signature import format

This document is the **canonical authoring contract** for `malware_signatures` entries —
the JSON shape consumed by `SignatureEngine`, the same engine both the scanner and
`guard:signature-sweep` use. It is a deep-dive companion to
[`docs/INCIDENT_IMPORT_FORMAT.md`](INCIDENT_IMPORT_FORMAT.md) section 6, which covers the
signature array in the context of a full incident file; this document covers the signature
entry itself in full detail, independent of the surrounding incident.

A machine-checkable version of this contract is at
[`docs/schemas/signature-import.schema.json`](schemas/signature-import.schema.json) (JSON
Schema draft 2020-12). A copyable example covering every `pattern_type` is at
[`docs/examples/signatures.example.json`](examples/signatures.example.json).

> Everything below was verified directly against the current
> `app/Modules/Scanner/SignatureEngine.php` and `app/Modules/Incidents/IncidentImportService.php`
> — including running every example in `signatures.example.json` through the real
> `SignatureEngine::match()` — rather than inferred from older documentation. If application
> code and this document ever disagree, treat that as a bug in whichever one is stale and open
> an issue; do not silently trust one side.

## 1. Where signature JSON is actually consumed

There is no standalone "upload one signature as JSON" endpoint. A signature is imported as one
entry of the `malware_signatures` array inside a
[`jura-server-guard-incident`](INCIDENT_IMPORT_FORMAT.md) file, via one of:

- **`guard:incident-import <file.json> [--dry-run]`** or the panel's **Incidents → Import
  incident file** — trusts the file's own `enabled` value (this path already requires a human
  to have reviewed a `--dry-run` first).
- **`guard:feed-import <incident_id> [--dry-run]`** (an incident already fetched via
  `guard:feed-check` / `guard:feed-update` from the
  [signatures feed](https://github.com/medvestnik/jura-server-guard-signatures-feed)) —
  **always** forces every signature it brings to `enabled=0`,
  `review_status=pending_feed_review`, regardless of what the file's `enabled` field says. An
  admin must explicitly approve each one afterwards via `guard:signature-enable <id>` or the
  Signatures page. This is the safety net for a compromised or over-broad feed release.

The manual **Signatures → New signature** panel form and **Create signature from finding**
flows write to the same `malware_signatures` table but go through individual form fields, not
raw JSON — this document is about the JSON import path specifically.

Both import paths upsert by **`slug`**: re-importing a signature with the same slug updates the
existing row (name, description, risk, type, pattern, extensions, `enabled`, review status) in
place instead of creating a duplicate.

## 2. Field reference

| Field | Required | Type | Notes |
|---|---|---|---|
| `name` | yes | string | Human-readable name. |
| `slug` | yes | string | Stable, unique. This is the upsert key. |
| `description` | no | string | Shown in the panel; used as the default match explanation. |
| `risk` | yes | string | One of `low`, `medium`, `high`, `critical`. |
| `type` | yes | string | Free-text finding type (e.g. `webshell`, `structural`, `suspicious_php`). Not a hard enum, but keep it consistent — it becomes the finding's `type` column and groups related findings. |
| `pattern_type` | yes | string | One of `hash`, `combo`, `regex`, `substring`, `structural`. See section 4. |
| `pattern_json` | yes | object | Shape depends on `pattern_type`. See section 4. |
| `target_extensions` | no | array\<string\> | Lowercase, no leading dot, e.g. `["php","phtml","phar"]`. Empty/omitted = every scanned file is a candidate. **This is the only scoping `SignatureEngine::match()` actually enforces** before running `pattern_json` against a file. |
| `target_paths` | no | array\<string\> | Stored and shown in reports, but **not currently read by the matching engine at all**. Do not rely on it to scope a signature — use `pattern_type: structural` (`path_regex` / `directory_names` / `path_contains`) instead. |
| `exclude_paths` | no | array\<string\> | Same caveat as `target_paths` — stored, not enforced. |
| `required_hits` | no | integer | Stored, not currently read by the matching engine. A match is pass/fail per `pattern_type`'s own rules, not a hit-count threshold against this field. |
| `enabled` | no | boolean | Defaults to `false` if omitted. **Ignored** on a feed import — see section 1. |
| `source` | no | string | Defaults to `incident:<incident.id>` when omitted. |

A handful of `malware_signatures` columns are **not part of the import JSON at all** — they are
set by the application itself and any value for them in an import file is ignored:
`id`, `source_finding_id`, `source_file_sha256`, `confidence`, `false_positive_notes`,
`incident_id`, `review_status`, `feed_release_tag`. These exist for auto-created signatures
(critical findings that seed a signature automatically — see README "Auto-created signatures
from critical findings"), AI-suggested signatures, and feed provenance/review tracking.

## 3. Validation performed on import

`IncidentImportService::validate()` rejects the whole file (not just the one bad entry) if any
`malware_signatures[i]` fails:

- `slug` is missing or empty.
- `name` is missing or empty.
- `risk` is not one of `low`, `medium`, `high`, `critical`.
- `type` is missing or not a string.
- `pattern_type` is not one of `hash`, `combo`, `regex`, `substring`, `structural`.
- `pattern_json` is not a JSON object.

The validator does **not** check that `pattern_json`'s internal shape matches its declared
`pattern_type` (e.g. a `hash` entry with no `sha256` key passes the importer's own validation
and is simply imported as a signature that can never match anything). Use
`docs/schemas/signature-import.schema.json` and/or `guard:signature-test` (section 6) to catch
that class of mistake before importing.

## 4. `pattern_json` by `pattern_type`

### `hash` — exact SHA-256 match

```json
{
  "sha256": [
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  ]
}
```

- `sha256` is required, a non-empty array of 64-character hex strings (case-insensitive; both
  sides are lowercased before comparing).
- Matches only when the scanned file's own SHA-256 is in the list **and** the file is
  non-empty. An empty file's hash
  (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`) can never match, even if
  listed — this prevents a signature accidentally matching every zero-byte file server-wide.

### `combo` — multiple required/optional markers, AND/OR/NOT combined

```json
{
  "all": ["php://input", "curl_exec"],
  "regex_all": ["/\\beval\\s*\\(/is"],
  "any": ["base64_decode", "str_rot13"],
  "regex_any": ["/\\bunpack\\s*\\(\\s*['\"]H\\*/i"],
  "not": ["// legitimate-vendor-marker"],
  "required_groups": [
    { "min": 2, "any": ["chmod(", "rename(", "unlink(", "fopen("] }
  ]
}
```

All keys are optional individually, but **at least one of `all` / `regex_all` / `any` /
`regex_any` / `not` / `required_groups` must be present** — `pattern_json` here is a nested
object, not the fixed-key kind, so a typo'd or unrecognized shape (e.g. authoring
`{"match": "all", "substrings": [...]}` instead of the real keys) has no way to be caught by
schema validation of the outer entry alone. `SignatureEngine::matchCombo()` **fails closed** on
this: an unrecognized shape never matches, rather than the pre-2026-09 behavior of silently
matching every targeted file server-wide (this exact bug shipped in signatures #221-224 and
produced tens of thousands of false "critical" findings before it was caught). Always test a
newly authored `combo` signature with `guard:signature-test` before enabling it.

Semantics:

- `all` — every substring must be present (case-insensitive `stripos`).
- `regex_all` — every regex must match. PHP PCRE, **with delimiters**, e.g. `"/eval\\s*\\(/i"`.
- `any` / `regex_any` — when either key is present, at least one hit from either list is
  required (they are evaluated together as a single "any of these" gate, not two independent
  gates).
- `not` — if **any** of these substrings is present anywhere in the content, the signature does
  **not** match, regardless of everything else. A hard exclusion.
- `required_groups` — each `{min, any, regex_any}` group independently requires at least `min`
  hits across its own `any`/`regex_any` lists (mix substrings and regexes freely within one
  group).

### `regex` — single content regex

```json
{ "regex": "#POST\\s+/index\\.php\\?option=com_jce&task=profiles\\.import#i" }
```

- `regex` is required, a PHP PCRE string with delimiters.
- Matches against whatever content was read for the file being checked. A request/log-shaped
  regex like the example above only makes sense against log lines, not PHP source — keep
  request-pattern signatures `enabled: false` unless you've confirmed the scanner path/content
  target is actually appropriate for the rule (see README "Request/log signatures should
  normally be `enabled: false`").

### `substring` — one or more plain markers

```json
{
  "any": ["distinctive-marker-a", "distinctive-marker-b"],
  "case_insensitive": true
}
```

- `any` (or its legacy alias `substring` — prefer `any` in new signatures) is required, a
  non-empty array of strings; any one hit matches.
- `case_insensitive` defaults to `true`.
- Avoid broad standalone markers such as common JavaScript/PHP function names that could occur
  legitimately — prefer `combo` with an `all`/`required_groups` constraint, an exact `hash`, or
  leave the signature disabled for review-only use.

### `structural` — path- and/or directory-layout-based

```json
{
  "path_regex": "#(^|/)images/wp-news\\.php$#i",
  "directory_names": ["404SBG"],
  "path_contains": ["/vendor/known-bad-fork/"],
  "require_path_and_content": true,
  "regex_any": ["/eval\\s*\\(\\s*base64_decode\\s*\\(/i"]
}
```

- `path_regex` — PCRE with delimiters, matched against the site-relative path.
- `directory_names` — matches when any listed name appears as a whole path segment (not a
  substring of a longer segment).
- `path_contains` — matches when any listed string is a plain substring of the relative path.
- `require_path_and_content` — when `true`, **both** a path-side signal (any of the three keys
  above) **and** a `regex_any` content match are required. Default is `false`: either side
  alone is enough.
- `regex_any` — content-side regex(es); same semantics as `combo`'s `regex_any`.

At least one of `path_regex` / `directory_names` / `path_contains` /
`same_directory_min_extension_variants`+`filename_stem_pattern` should be present, or the
signature can only ever match through `regex_any` alone (equivalent to a weaker `regex`
signature).

#### Multi-extension numeric-ID payload spray

A separate, narrower detector inside `structural`, for droppers that write the same payload
under one numeric-looking filename stem across several case/extension variants in the same
directory (`123456.php`, `123456.PHP`, `123456.phtml`, ...) to survive extension-based
execution blocks:

```json
{
  "filename_stem_pattern": "/^[0-9]{5,}$/",
  "same_directory_min_extension_variants": 3,
  "extensions": ["php", "PHP", "phtml", "pht"]
}
```

All three keys (`filename_stem_pattern`, `same_directory_min_extension_variants`, `extensions`)
must be present together to activate. When active: the file being checked must itself match
`filename_stem_pattern` (against its basename without extension) and have an extension in
`extensions`; the engine then checks how many sibling files with the same stem and a different
extension from `extensions` actually exist in the same directory, and matches only if that
count is `>= same_directory_min_extension_variants`.

## 5. Testing before you enable a signature

Always test a newly authored signature against a known file before relying on it, especially a
`combo` or `structural` one:

```bash
php artisan guard:signature-test <signature_id> /path/to/file
```

To check every already-inventoried site for one specific signature right now (fast — no other
signatures, no heuristic rules, no log correlation), instead of waiting for or triggering a
full scan:

```bash
php artisan guard:signature-sweep <signature_id>
```

(also available as a button on the signature's detail page in the panel).

## 6. Pre-import checklist

1. `pattern_type` is one of `hash`, `combo`, `regex`, `substring`, `structural`.
2. `pattern_json` actually has the keys that `pattern_type` requires — validate against
   `docs/schemas/signature-import.schema.json`, since the importer itself does not check this.
3. Every `sha256` value is exactly 64 hex characters.
4. A `combo` signature has at least one of `all`/`regex_all`/`any`/`regex_any`/`not`/
   `required_groups` — an empty or unrecognized `pattern_json` shape now correctly never
   matches (it used to match everything; see section 4), but an accidentally-empty signature is
   still a signature that will never fire, which is its own kind of silent failure worth
   catching before shipping it.
5. `target_extensions` is set when the signature should only apply to certain file types — an
   empty list runs `pattern_json` against every scanned file.
6. Not relying on `target_paths` / `exclude_paths` to scope matching — use `structural`'s
   path-side keys instead if path scoping is actually needed.
7. `enabled` is deliberately chosen — `true` only for signatures confirmed against real evidence
   (an exact hash, or content markers tested with `guard:signature-test`); request/log-pattern
   `regex` signatures are normally `enabled: false`.
8. Ran `guard:signature-test` (or `guard:signature-sweep` in dry conditions) against at least
   one known-matching and one known-non-matching file.
9. `guard:incident-import ... --dry-run` reviewed before the real import.

## 7. Canonical example

A copyable example covering all five `pattern_type` values is at
[`docs/examples/signatures.example.json`](examples/signatures.example.json). To use it in a
real import, wrap it under `malware_signatures` inside a full incident skeleton — see
[`docs/examples/incident-v1.example.json`](examples/incident-v1.example.json) and
[`docs/INCIDENT_IMPORT_FORMAT.md`](INCIDENT_IMPORT_FORMAT.md) for the surrounding shape.
