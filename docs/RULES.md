# Jura AV Monitor rules

Default rules are defined in `rules/default-rules.php` and seeded into the `rules` and `allowlist_rules` tables.

## Detection categories

- Known malware strings: `blackhat.pw`, `_bh_chk`, `ALFA_DATA`, `alfacgiapi`, `Leviathan Defender`, `deploy=true`, `fileloc=`, `?delivery`, and similar indicators.
- Suspicious PHP functions: `eval($_`, `assert($_`, `system($_`, `shell_exec($_`, `proc_open($_`, `base64_decode(`, `gzinflate(`, `str_rot13(`.
- Suspicious locations: PHP files under uploads, images, cache, tmp/temp, ALFA paths, and hidden `.tmb` widget paths.
- Suspicious names: `AuthControlIer.php`, `whewr.php`, `mah.php`, `gallery888.php`, and related webshell filenames.
- Hex names: `[a-f0-9]{32}\.php`.
- Important core changes: `index.php`, `.htaccess`, `.user.ini`, `wp-includes/plugin.php`, WordPress core/plugin paths, Joomla `configuration.php`, and OpenCart config files.

## False positives and allowlist

Built-in allowlist entries cover common legitimate loaders and module files. Allowlisted files can still be shown as low-risk after changes, but should not be automatically quarantined.

## Log analyzer

The log analyzer searches for suspicious requests such as `?delivery`, `?deploy=true`, `?_bh_chk`, `fileloc=`, `ALFA_DATA`, `alfacgiapi`, known webshell names, suspicious loader referrers, and POSTs to unknown PHP files. It ignores normal delivery images and URLs like `/delivery`, `/ua/delivery`, and `header-delivery.svg`.
