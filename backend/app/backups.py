"""Consistent SQLite snapshots with the encryption key and SSH identity."""
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import DATA_DIR, DB_PATH, db, get_setting, now, set_setting

BACKUP_DIR = DATA_DIR / "backups"
KEEP_DAYS = 14


def create() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    destination = BACKUP_DIR / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination.mkdir(mode=0o700)
    with sqlite3.connect(DB_PATH) as source, sqlite3.connect(destination / "cerberus.db") as target:
        source.backup(target)
    for name in ("master.key",):
        path = DATA_DIR / name
        if path.exists():
            shutil.copy2(path, destination / name)
    ssh = DATA_DIR / "ssh"
    if ssh.exists():
        shutil.copytree(ssh, destination / "ssh")
    if (destination / "master.key").exists():
        (destination / "master.key").chmod(0o600)
    with db() as conn:
        set_setting(conn, "backup_last_run", now())
    cutoff = datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)
    for child in BACKUP_DIR.iterdir():
        if child.is_dir():
            try:
                when = datetime.strptime(child.name, "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if when < cutoff:
                shutil.rmtree(child)
    return destination


def tick():
    with db() as conn:
        last = get_setting(conn, "backup_last_run")
    if last and last[:10] == now()[:10]:
        return
    create()
