#!/usr/bin/env bash
set -euo pipefail
APP_DIR="/opt/jura-server-guard"
PORT="8765"
ADMIN_EMAIL="${JURA_ADMIN_EMAIL:-admin@example.com}"
PHP_BIN=""
PHP_VERSION_SELECTED=""
COMPOSER_LABEL=""

if [[ "${EUID}" -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi

append_env_value() {
  local key="$1"
  local value="$2"
  local escaped_value
  escaped_value=$(printf '%s' "$value" | sed 's/[\\&]/\\&/g')
  if grep -q "^${key}=" .env; then
    sed -i "s#^${key}=.*#${key}=${escaped_value}#" .env
  else
    echo "${key}=${value}" >> .env
  fi
}

php_candidate_info() {
  local candidate="$1"
  local info

  [[ -f "$candidate" && -x "$candidate" ]] || return 1

  if ! info=$("$candidate" -r '
    $okVersion = version_compare(PHP_VERSION, "8.2.0", ">=");
    $hasPdo = extension_loaded("PDO");
    $hasPdoSqlite = extension_loaded("pdo_sqlite");
    $hasSqlite3 = extension_loaded("sqlite3");
    echo PHP_VERSION . "|" . ($okVersion ? "yes" : "no") . "|" . ($hasPdo ? "yes" : "no") . "|" . ($hasPdoSqlite ? "yes" : "no") . "|" . ($hasSqlite3 ? "yes" : "no");
  ' 2>/dev/null); then
    return 1
  fi

  IFS='|' read -r version ok_version has_pdo has_pdo_sqlite has_sqlite3 <<<"$info"

  if [[ "$ok_version" != "yes" || "$has_pdo" != "yes" || "$has_pdo_sqlite" != "yes" ]]; then
    return 1
  fi

  printf '%s|%s\n' "$version" "$has_sqlite3"
}

sort_php_candidates_by_version() {
  local line
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    local version path sqlite3
    IFS='|' read -r version path sqlite3 <<<"$line"
    printf '%s|%s|%s\n' "$version" "$path" "$sqlite3"
  done | sort -t'|' -k1,1Vr
}

detect_php_binary() {
  local candidates=()
  local seen=""
  local path_php=""
  local candidate=""
  local info=""
  local version=""
  local sqlite3_loaded=""
  local recommended_index=0
  local selected_index=0
  local highest_index=0
  local selected=""
  local selected_sqlite3=""
  local sorted=""
  local highest_path=""
  local i=0

  add_candidate() {
    local item="$1"
    [[ -n "$item" ]] || return 0
    case "$item" in
      /*) ;;
      *) item=$(command -v "$item" 2>/dev/null || true) ;;
    esac
    [[ -n "$item" ]] || return 0
    case ":$seen:" in
      *:"$item":*) return 0 ;;
    esac
    seen="${seen}:${item}"
    candidates+=("$item")
  }

  if [[ -n "${JURA_PHP_BIN:-}" ]]; then add_candidate "$JURA_PHP_BIN"; fi
  path_php=$(command -v php 2>/dev/null || true)
  add_candidate "$path_php"
  add_candidate "/opt/php85/bin/php"
  add_candidate "/opt/php84/bin/php"
  add_candidate "/opt/php83/bin/php"
  add_candidate "/opt/php82/bin/php"
  add_candidate "/usr/bin/php"
  add_candidate "/usr/local/bin/php"

  local valid_paths=()
  local valid_versions=()
  local valid_sqlite3=()
  local jura_index=0
  local php83_index=0

  for candidate in "${candidates[@]}"; do
    if info=$(php_candidate_info "$candidate"); then
      IFS='|' read -r version sqlite3_loaded <<<"$info"
      valid_paths+=("$candidate")
      valid_versions+=("$version")
      valid_sqlite3+=("$sqlite3_loaded")
      if [[ -n "${JURA_PHP_BIN:-}" && "$candidate" == "$JURA_PHP_BIN" ]]; then
        jura_index=${#valid_paths[@]}
      fi
      if [[ "$candidate" == "/opt/php83/bin/php" ]]; then
        php83_index=${#valid_paths[@]}
      fi
    elif [[ -n "${JURA_PHP_BIN:-}" && "$candidate" == "$JURA_PHP_BIN" ]]; then
      echo "Warning: JURA_PHP_BIN=$JURA_PHP_BIN is not usable or lacks PHP 8.2+/PDO/pdo_sqlite; trying other PHP binaries." >&2
    fi
  done

  if [[ ${#valid_paths[@]} -eq 0 ]]; then
    cat >&2 <<'EOF'
PHP 8.2+ with PDO and pdo_sqlite is required.
Checked JURA_PHP_BIN, php from PATH, /opt/php85/bin/php, /opt/php84/bin/php, /opt/php83/bin/php, /opt/php82/bin/php, /usr/bin/php, and /usr/local/bin/php.
On ISPmanager/AlmaLinux, install or enable an alternative PHP such as /opt/php83/bin/php without changing native system PHP.
EOF
    exit 1
  fi

  for ((i=0; i<${#valid_paths[@]}; i++)); do
    sorted+="${valid_versions[$i]}|${valid_paths[$i]}|${valid_sqlite3[$i]}"$'\n'
  done
  sorted=$(printf '%s' "$sorted" | sort_php_candidates_by_version | head -n 1)
  IFS='|' read -r version highest_path selected_sqlite3 <<<"$sorted"
  for ((i=0; i<${#valid_paths[@]}; i++)); do
    if [[ "${valid_paths[$i]}" == "$highest_path" ]]; then highest_index=$((i+1)); break; fi
  done

  if [[ ${#valid_paths[@]} -eq 1 ]]; then
    selected_index=1
  elif [[ -t 0 && -t 1 ]]; then
    if [[ $php83_index -gt 0 ]]; then recommended_index=$php83_index; else recommended_index=$highest_index; fi
    echo "Multiple suitable PHP binaries found:"
    for ((i=0; i<${#valid_paths[@]}; i++)); do
      printf '[%d] %s — %s\n' "$((i+1))" "${valid_paths[$i]}" "${valid_versions[$i]}"
    done
    read -r -p "Select PHP binary [default: recommended ${valid_paths[$((recommended_index-1))]}]: " selected
    if [[ "$selected" =~ ^[0-9]+$ && "$selected" -ge 1 && "$selected" -le ${#valid_paths[@]} ]]; then
      selected_index=$selected
    else
      selected_index=$recommended_index
    fi
  else
    if [[ $jura_index -gt 0 ]]; then
      selected_index=$jura_index
    elif [[ $php83_index -gt 0 ]]; then
      selected_index=$php83_index
    else
      selected_index=$highest_index
    fi
  fi

  PHP_BIN="${valid_paths[$((selected_index-1))]}"
  PHP_VERSION_SELECTED="${valid_versions[$((selected_index-1))]}"
  selected_sqlite3="${valid_sqlite3[$((selected_index-1))]}"

  if [[ "$selected_sqlite3" != "yes" ]]; then
    echo "Warning: PHP sqlite3 extension is not loaded for $PHP_BIN. pdo_sqlite is available, so installation can continue." >&2
  fi
}

generate_admin_password() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 12
    return 0
  fi

  "$PHP_BIN" -r 'echo bin2hex(random_bytes(12));'
}

install_composer_if_needed() {
  local system_composer
  system_composer=$(command -v composer 2>/dev/null || true)
  if [[ -n "$system_composer" ]]; then
    COMPOSER_BIN="$system_composer"
    COMPOSER_LABEL="system composer ($system_composer)"
    return 0
  fi

  mkdir -p "$APP_DIR/bin"
  COMPOSER_BIN="$APP_DIR/bin/composer.phar"
  COMPOSER_LABEL="bundled composer.phar ($COMPOSER_BIN)"
  if [[ -f "$COMPOSER_BIN" ]]; then
    return 0
  fi

  echo "Composer not found in PATH; downloading bundled composer.phar..."
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL https://getcomposer.org/download/latest-stable/composer.phar -o "$COMPOSER_BIN"
  elif command -v wget >/dev/null 2>&1; then
    wget -q https://getcomposer.org/download/latest-stable/composer.phar -O "$COMPOSER_BIN"
  else
    echo "Composer is not installed and neither curl nor wget is available to download composer.phar." >&2
    exit 1
  fi
  chmod 0755 "$COMPOSER_BIN"
}

detect_php_binary
mkdir -p "$APP_DIR"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$SRC_DIR" != "$APP_DIR" ]]; then
  rsync -a --delete --exclude='.git' --exclude='.env' --exclude='storage/database.sqlite' "$SRC_DIR/" "$APP_DIR/"
fi
cd "$APP_DIR"
if [[ ! -f .env ]]; then cp .env.example .env; fi
mkdir -p storage/logs storage/framework/cache storage/framework/sessions storage/framework/views bin
append_env_value "DB_DATABASE" "$APP_DIR/storage/database.sqlite"
append_env_value "JURA_PHP_BIN" "$PHP_BIN"
touch "$APP_DIR/storage/database.sqlite"
install_composer_if_needed
"$PHP_BIN" "$COMPOSER_BIN" install --no-dev --optimize-autoloader
"$PHP_BIN" artisan key:generate
"$PHP_BIN" artisan migrate --force
ADMIN_PASSWORD="$(generate_admin_password)"
"$PHP_BIN" artisan guard:create-admin "$ADMIN_EMAIL" "$ADMIN_PASSWORD" >/dev/null
"$PHP_BIN" artisan config:cache
cat >/etc/systemd/system/jura-server-guard.service <<EOF
[Unit]
Description=Jura Server Guard Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$PHP_BIN artisan serve --host=127.0.0.1 --port=$PORT
Restart=always
RestartSec=5
Environment=APP_ENV=production

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/jura-server-guard-scan.service <<EOF
[Unit]
Description=Jura Server Guard scheduled scan

[Service]
Type=oneshot
WorkingDirectory=$APP_DIR
ExecStart=$PHP_BIN $APP_DIR/artisan guard:scan
EOF
cat >/etc/systemd/system/jura-server-guard-scan.timer <<EOF
[Unit]
Description=Run Jura Server Guard scan every 10 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
Unit=jura-server-guard-scan.service

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now jura-server-guard.service
systemctl enable --now jura-server-guard-scan.timer
cat <<EOF
Jura Server Guard installed.
Panel: http://127.0.0.1:$PORT
Default login: $ADMIN_EMAIL
Default password: $ADMIN_PASSWORD
Config: $APP_DIR/.env
PHP binary: $PHP_BIN
PHP version: $PHP_VERSION_SELECTED
Composer: $COMPOSER_LABEL
EOF
