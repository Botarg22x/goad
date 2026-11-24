#!/usr/bin/env bash
set -euo pipefail

lab_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
backup_dir="$lab_dir/backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$backup_dir"

docker compose -f "$lab_dir/compose.yaml" exec -T db \
  sh -c 'exec mysqldump --single-transaction --quick -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' \
  > "$backup_dir/wordpress.sql"

docker compose -f "$lab_dir/compose.yaml" exec -T wordpress \
  tar -C /var/www/html -czf - wp-content \
  > "$backup_dir/wp-content.tar.gz"

printf 'Резервная копия: %s\n' "$backup_dir"
