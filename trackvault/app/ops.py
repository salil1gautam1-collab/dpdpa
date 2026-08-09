"""Operational maintenance commands (run on a schedule in production).

  python -m app.ops purge-sessions          delete expired/revoked sessions
  python -m app.ops retention --months 24   delete snapshots older than N months
  python -m app.ops erase --company <id>    DPDPA erasure: remove a company + all its data
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from .db import SessionLocal
from .models import (AuditLog, Company, Connector, Notification, QuestionnaireAnswer,
                     Snapshot, User, UserSession)


def purge_sessions() -> int:
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        res = db.execute(delete(UserSession).where(
            (UserSession.expires_at < now) | (UserSession.revoked.is_(True))))
        db.commit()
        print(f"purged {res.rowcount} expired/revoked sessions")
        return res.rowcount or 0
    finally:
        db.close()


def retention(months: int, apply: bool) -> int:
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=30 * months)
        old = [s for s in db.execute(select(Snapshot)).scalars()
               if s.created_at and s.created_at < cutoff]
        # keep the latest snapshot per company regardless of age (audit baseline)
        latest_ids = set()
        for c in db.execute(select(Company)).scalars():
            latest = db.execute(select(Snapshot).where(Snapshot.company_id == c.id)
                                .order_by(Snapshot.scan_id.desc())).scalars().first()
            if latest:
                latest_ids.add(latest.id)
        victims = [s for s in old if s.id not in latest_ids]
        print(f"{len(victims)} snapshot(s) older than {months} months eligible for deletion "
              f"(latest per company always kept).")
        if apply:
            for s in victims:
                db.delete(s)
            db.commit()
            print(f"deleted {len(victims)} snapshot(s)")
        else:
            print("dry run — pass --apply to delete")
        return len(victims)
    finally:
        db.close()


def monitor() -> int:
    """Re-assess every company whose monitoring is due; alert on changes.
    Intended to run on a schedule (cron / Task Scheduler), e.g. hourly or daily."""
    from datetime import datetime, timedelta, timezone
    from .services.scan_service import run_and_notify
    db = SessionLocal()
    ran = 0
    try:
        now = datetime.now(timezone.utc)
        due = [c for c in db.execute(select(Company)).scalars()
               if c.monitor_frequency in ("weekly", "monthly")
               and c.next_monitor_at is not None and c.next_monitor_at <= now]
        for c in due:
            skip_web = not (c.sites and (c.scan_consent or {}).get("granted"))
            try:
                snap, alerts = run_and_notify(db, c, skip_web=skip_web, actor_email="monitor")
                print(f"monitored {c.name}: score {snap.score}%, {len(alerts)} alert(s)")
            except Exception as ex:  # pragma: no cover
                print(f"monitor failed for {c.name}: {ex}")
            days = 7 if c.monitor_frequency == "weekly" else 30
            c.next_monitor_at = now + timedelta(days=days)
            db.commit()
            ran += 1
        if not due:
            print("no companies due for monitoring")
        return ran
    finally:
        db.close()


def erase(company_id: str) -> None:
    db = SessionLocal()
    try:
        c = db.get(Company, company_id)
        if not c:
            print("company not found")
            return
        name = c.name
        for model in (Snapshot, Connector, QuestionnaireAnswer, Notification):
            db.execute(delete(model).where(model.company_id == company_id))
        for u in db.execute(select(User).where(User.company_id == company_id)).scalars():
            db.delete(u)
        db.add(AuditLog(action="company.erase", target_type="company", target_id=company_id,
                        detail={"name": name, "reason": "DPDPA erasure / engagement end"}))
        db.delete(c)
        db.commit()
        print(f"erased company {name} and all associated data")
    finally:
        db.close()


def watch() -> None:
    """Scheduled regulatory watch: scan official sources for new DPDP documents.
    Run daily from cron alongside `monitor`."""
    db = SessionLocal()
    try:
        from .services.reg_watch import check_now
        res = check_now(db)
        print(f"regulatory watch: {res['new']} new item(s); "
              f"{len(res['errors'])} source error(s)")
        for t in res["titles"]:
            print("  new:", t)
        for e in res["errors"]:
            print("  err:", e)
    finally:
        db.close()


def main() -> None:
    ap = argparse.ArgumentParser(prog="app.ops")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("purge-sessions")
    sub.add_parser("monitor")
    sub.add_parser("watch")
    r = sub.add_parser("retention")
    r.add_argument("--months", type=int, default=24)
    r.add_argument("--apply", action="store_true")
    e = sub.add_parser("erase")
    e.add_argument("--company", required=True)
    args = ap.parse_args()

    if args.cmd == "purge-sessions":
        purge_sessions()
    elif args.cmd == "monitor":
        monitor()
    elif args.cmd == "watch":
        watch()
    elif args.cmd == "retention":
        retention(args.months, args.apply)
    elif args.cmd == "erase":
        erase(args.company)


if __name__ == "__main__":
    main()
