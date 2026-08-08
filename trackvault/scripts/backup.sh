#!/usr/bin/env bash
# Nightly Postgres backup. Run from the compose project dir, e.g. via cron:
#   0 2 * * *  cd /opt/trackvault && ./scripts/backup.sh >> /var/log/tv-backup.log 2>&1
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
KEEP_DAYS="${KEEP_DAYS:-14}"
STAMP="$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "[$(date)] backing up database..."
docker compose exec -T db pg_dump -U "${POSTGRES_USER:-trackvault}" "${POSTGRES_DB:-trackvault}" \
  | gzip > "$BACKUP_DIR/trackvault-$STAMP.sql.gz"

echo "[$(date)] pruning backups older than $KEEP_DAYS days..."
find "$BACKUP_DIR" -name 'trackvault-*.sql.gz' -mtime +"$KEEP_DAYS" -delete

echo "[$(date)] backup complete: $BACKUP_DIR/trackvault-$STAMP.sql.gz"
