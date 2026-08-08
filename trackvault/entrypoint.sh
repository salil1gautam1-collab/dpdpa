#!/usr/bin/env bash
set -e

echo "Waiting for database..."
python - <<'PY'
import os, time
import psycopg
url = os.environ.get("TRACKVAULT_DATABASE_URL", "postgresql://trackvault:trackvault@db:5432/trackvault").replace("+psycopg", "")
for i in range(30):
    try:
        psycopg.connect(url, connect_timeout=3).close()
        print("database ready"); break
    except Exception as e:
        print(f"  waiting ({i}): {e}"); time.sleep(2)
else:
    raise SystemExit("database not reachable")
PY

echo "Running migrations..."
alembic upgrade head

echo "Seeding (rulebooks, provider org, bootstrap admin)..."
python -m app.seed

echo "Starting TrackVault..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${WEB_CONCURRENCY:-2}
