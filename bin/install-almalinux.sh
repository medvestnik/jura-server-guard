#!/usr/bin/env bash
set -euo pipefail
APP_DIR="/opt/jura-server-guard"
PORT="${JURA_PORT:-8765}"
BIND_HOST="${JURA_BIND_HOST:-127.0.0.1}"
DB_CONNECTION="${JURA_DB_CONNECTION:-}"
DB_HOST="${JURA_DB_HOST:-127.0.0.1}"
DB_PORT="${JURA_DB_PORT:-3306}"
DB_DATABASE="${JURA_DB_DATABASE:-jura_server_guard}"
DB_USERNAME="${JURA_DB_USERNAME:-jsg}"
DB_PASSWORD="${JURA_DB_PASSWORD:-}"
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
    echo PHP_VERSION . "|" . ($okVersion ? "yes" : "no") . "|" . ($hasPdo ? "yes" : "no") . "|" . ($hasPdoSqlite ? "yes" : "no") . "|" . ($hasSqlite3 ? "yes" : "no") . "|" . (extension_loaded("pdo_mysql") ? "yes" : "no");
  ' 2>/dev/null); then
    return 1
  fi

  IFS='|' read -r version ok_version has_pdo has_pdo_sqlite has_sqlite3 has_pdo_mysql <<<"$info"

  if [[ "$ok_version" != "yes" || "$has_pdo" != "yes" ]]; then
    return 1
  fi
  if [[ "$DB_CONNECTION" == "mysql" && "$has_pdo_mysql" != "yes" ]]; then
    return 1
  fi
  if [[ "$DB_CONNECTION" == "sqlite" && "$has_pdo_sqlite" != "yes" ]]; then
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
      echo "Warning: JURA_PHP_BIN=$JURA_PHP_BIN is not usable or lacks PHP 8.2+/PDO/selected DB extension; trying other PHP binaries." >&2
    fi
  done

  if [[ ${#valid_paths[@]} -eq 0 ]]; then
    cat >&2 <<'EOF'
PHP 8.2+ with PDO and the selected DB extension (pdo_mysql for MySQL or pdo_sqlite for SQLite) is required.
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

  if [[ "$DB_CONNECTION" == "sqlite" && "$selected_sqlite3" != "yes" ]]; then
    echo "Warning: PHP sqlite3 extension is not loaded for $PHP_BIN. pdo_sqlite is available, so installation can continue." >&2
  fi
}

generate_admin_password() {
  local password=""
  if command -v openssl >/dev/null 2>&1; then
    password=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9_@%+=' | cut -c1-24 || true)
  fi
  if [[ -z "$password" || ${#password} -lt 16 ]]; then
    password=$("$PHP_BIN" -r 'echo bin2hex(random_bytes(12));')
  fi
  printf '%s\n' "$password"
}

select_database_backend() {
  if [[ -z "$DB_CONNECTION" ]]; then
    DB_CONNECTION="mysql"
    if [[ -t 0 && -t 1 ]]; then
      echo "Select database backend:"
      echo "[1] MariaDB/MySQL recommended for production"
      echo "[2] SQLite only for small/local installations"
      read -r -p "Database backend [default: 1]: " db_choice
      if [[ "$db_choice" == "2" ]]; then DB_CONNECTION="sqlite"; fi
    fi
  fi
  DB_CONNECTION=$(printf '%s' "$DB_CONNECTION" | tr '[:upper:]' '[:lower:]')
  if [[ "$DB_CONNECTION" != "mysql" && "$DB_CONNECTION" != "sqlite" ]]; then echo "Unsupported JURA_DB_CONNECTION=$DB_CONNECTION" >&2; exit 1; fi
}

configure_database_env() {
  append_env_value "DB_CONNECTION" "$DB_CONNECTION"
  if [[ "$DB_CONNECTION" == "mysql" ]]; then
    if [[ -t 0 && -t 1 ]]; then
      read -r -p "MySQL host [$DB_HOST]: " v; [[ -n "$v" ]] && DB_HOST="$v"
      read -r -p "MySQL port [$DB_PORT]: " v; [[ -n "$v" ]] && DB_PORT="$v"
      read -r -p "MySQL database [$DB_DATABASE]: " v; [[ -n "$v" ]] && DB_DATABASE="$v"
      read -r -p "MySQL username [$DB_USERNAME]: " v; [[ -n "$v" ]] && DB_USERNAME="$v"
      if [[ -z "$DB_PASSWORD" ]]; then read -r -s -p "MySQL password: " DB_PASSWORD; echo; fi
    fi
    append_env_value "DB_HOST" "$DB_HOST"
    append_env_value "DB_PORT" "$DB_PORT"
    append_env_value "DB_DATABASE" "$DB_DATABASE"
    append_env_value "DB_USERNAME" "$DB_USERNAME"
    append_env_value "DB_PASSWORD" "$DB_PASSWORD"
    append_env_value "DB_CHARSET" "utf8mb4"
    append_env_value "DB_COLLATION" "utf8mb4_unicode_ci"
    if ! DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_DATABASE="$DB_DATABASE" DB_USERNAME="$DB_USERNAME" DB_PASSWORD="$DB_PASSWORD" "$PHP_BIN" -r '$h=getenv("DB_HOST");$p=getenv("DB_PORT");$d=getenv("DB_DATABASE");$u=getenv("DB_USERNAME");$pw=getenv("DB_PASSWORD");try{new PDO("mysql:host=$h;port=$p;dbname=$d;charset=utf8mb4",$u,$pw,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);}catch(Throwable $e){fwrite(STDERR,$e->getMessage().PHP_EOL);exit(1);}' ; then
      echo "Cannot connect to MySQL database. Create DB/user first or provide correct JURA_DB_* values." >&2
      exit 1
    fi
  else
    append_env_value "DB_DATABASE" "$APP_DIR/storage/database.sqlite"
    touch "$APP_DIR/storage/database.sqlite"
  fi
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

select_database_backend
detect_php_binary
mkdir -p "$APP_DIR"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$SRC_DIR" != "$APP_DIR" ]]; then
  rsync -a --delete --exclude='.git' --exclude='.env' --exclude='storage/database.sqlite' "$SRC_DIR/" "$APP_DIR/"
fi
cd "$APP_DIR"
if [[ ! -f .env ]]; then cp .env.example .env; fi
mkdir -p storage/logs storage/framework/cache storage/framework/sessions storage/framework/views bin
configure_database_env
append_env_value "JURA_PHP_BIN" "$PHP_BIN"
append_env_value "JURA_PAGINATION_OPTIONS" "20,50,100,200,500,all"
append_env_value "JURA_PAGINATION_DEFAULT" "50"
append_env_value "JURA_WEB_ACTIONS_ENABLED" "false"
append_env_value "JURA_FIREWALL_ACTIONS_ENABLED" "false"
append_env_value "JURA_FIREWALL_BACKEND" "auto"
append_env_value "JURA_FIREWALL_CMD" "/usr/bin/firewall-cmd"
append_env_value "JURA_FIREWALL_BLOCK_ZONE" "drop"
append_env_value "JURA_IPTABLES_CMD" "/usr/sbin/iptables"
append_env_value "JURA_IP6TABLES_CMD" "/usr/sbin/ip6tables"
append_env_value "JURA_IPTABLES_SAVE_CMD" "/usr/sbin/iptables-save"
append_env_value "JURA_IP6TABLES_SAVE_CMD" "/usr/sbin/ip6tables-save"
append_env_value "JURA_IPTABLES_INIT_CMD" "/usr/libexec/iptables/iptables.init"
append_env_value "JURA_IP6TABLES_INIT_CMD" "/usr/libexec/iptables/ip6tables.init"
append_env_value "JURA_IPTABLES_RULES_FILE" "/etc/sysconfig/iptables"
append_env_value "JURA_IP6TABLES_RULES_FILE" "/etc/sysconfig/ip6tables"
append_env_value "JURA_IPTABLES_ENABLE_SERVICE" "true"
append_env_value "JURA_SYSTEMCTL_CMD" "/usr/bin/systemctl"
append_env_value "JURA_BIND_HOST" "$BIND_HOST"
append_env_value "JURA_PORT" "$PORT"
append_env_value "JURA_SCAN_INTERVAL_MINUTES" "30"
append_env_value "JURA_TIMER_SCAN_PROFILE" "fast"
append_env_value "JURA_LOG_SCAN_INTERVAL_MINUTES" "5"
append_env_value "JURA_SCAN_OLD_DUBL_BY_DEFAULT" "false"
append_env_value "JURA_SCAN_STORAGE_BY_DEFAULT" "false"
append_env_value "JURA_HASH_ALL_FILES" "false"
install_composer_if_needed
"$PHP_BIN" "$COMPOSER_BIN" install --no-dev --optimize-autoloader
"$PHP_BIN" artisan key:generate
if ! "$PHP_BIN" artisan migrate --force; then
  echo "ERROR: Database migration failed; likely a DB connectivity, permissions, charset, or migration/index error." >&2
  echo "Installer stopped before creating systemd units. Fix the database error, then rerun the installer." >&2
  exit 1
fi
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
ExecStart=$PHP_BIN artisan serve --host=$BIND_HOST --port=$PORT
Restart=always
RestartSec=5
Environment=APP_ENV=production

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now jura-server-guard.service
JURA_APP_DIR="$APP_DIR" JURA_PHP_BIN="$PHP_BIN" bash "$APP_DIR/bin/install-scan-timers.sh"
cat <<EOF
Jura Server Guard installed.
Panel: http://$BIND_HOST:$PORT
Default login: $ADMIN_EMAIL
Default password: $ADMIN_PASSWORD
Config: $APP_DIR/.env
PHP binary: $PHP_BIN
PHP version: $PHP_VERSION_SELECTED
DB backend: $DB_CONNECTION
Composer: $COMPOSER_LABEL
EOF
