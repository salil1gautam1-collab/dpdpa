#!/usr/bin/env bash
# Restore a Postgres backup created by backup.sh.
#   ./scripts/restore.sh backups/trackvault-YYYYMMDD-HHMMSS.sql.gz
set -euo pipefail

FILE="${1:?usage: restore.sh <backup.sql.gz>}"
echo "This will OVERWRITE the current database with $FILE."
read -r -p "Type 'yes' to continue: " confirm
[ "$confirm" = "yes" ] || { echo "aborted"; exit 1; }

gunzip -c "$FILE" | docker compose exec -T db psql -U "${POSTGRES_USER:-trackvault}" "${POSTGRES_DB:-trackvault}"
echo "restore complete."
