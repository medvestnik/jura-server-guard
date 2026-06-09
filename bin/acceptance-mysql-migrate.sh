#!/usr/bin/env bash
set -euo pipefail

DB_NAME="${JURA_TEST_DB_DATABASE:-jura_server_guard_acceptance}"
DB_USER="${JURA_TEST_DB_USERNAME:-${DB_USERNAME:-root}}"
DB_PASS="${JURA_TEST_DB_PASSWORD:-${DB_PASSWORD:-}}"
DB_HOST="${JURA_TEST_DB_HOST:-${DB_HOST:-127.0.0.1}}"
DB_PORT="${JURA_TEST_DB_PORT:-${DB_PORT:-3306}}"
PHP_BIN="${JURA_PHP_BIN:-php}"
MYSQL_BIN="${MYSQL_BIN:-mysql}"
ROOT_USER="${JURA_TEST_DB_ROOT_USER:-root}"
ROOT_PASS="${JURA_TEST_DB_ROOT_PASSWORD:-}"
ROOT_ARGS=(--host="$DB_HOST" --port="$DB_PORT" --user="$ROOT_USER")
if [[ -n "$ROOT_PASS" ]]; then ROOT_ARGS+=(--password="$ROOT_PASS"); fi

if ! command -v "$MYSQL_BIN" >/dev/null 2>&1; then
  echo "mysql client not found; install mysql/mariadb client or set MYSQL_BIN." >&2
  exit 1
fi

"$MYSQL_BIN" "${ROOT_ARGS[@]}" <<SQL
DROP DATABASE IF EXISTS \`$DB_NAME\`;
CREATE DATABASE \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
SQL

cleanup() {
  "$MYSQL_BIN" "${ROOT_ARGS[@]}" -e "DROP DATABASE IF EXISTS \`$DB_NAME\`;" >/dev/null 2>&1 || true
}
trap cleanup EXIT

export DB_CONNECTION=mysql
export DB_HOST="$DB_HOST"
export DB_PORT="$DB_PORT"
export DB_DATABASE="$DB_NAME"
export DB_USERNAME="$DB_USER"
export DB_PASSWORD="$DB_PASS"
export DB_CHARSET=utf8mb4

"$PHP_BIN" artisan migrate --force
"$PHP_BIN" artisan guard:db-stats
