"""Optional per-profile history of configured service IDs (no accounts or content)."""

import os
import re
import sqlite3
from pathlib import Path


def _state_path(state_dir):
    root = (
        Path(
            state_dir
            or os.environ.get("XDG_STATE_HOME")
            or Path.home() / ".local" / "state"
        )
        / "sentinel-security"
    )
    path = root / "connections.sqlite"
    if root.is_symlink() or path.is_symlink():
        raise ValueError("linked Sentinel state is not supported")
    return path


def recall(host, profile, services, state_dir=None):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", profile):
        raise ValueError("invalid profile label")
    path = _state_path(state_dir)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # SQLite handles overlapping scheduled checks. State is isolated by host + profile.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(fd)
    db = sqlite3.connect(path, timeout=5)
    try:
        with db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS seen(host TEXT, profile TEXT, service TEXT, PRIMARY KEY(host,profile,service))"
            )
            configured = {
                row["service"] for row in services if "configured" in row["evidence"]
            }
            db.executemany(
                "INSERT OR IGNORE INTO seen VALUES(?,?,?)",
                [(host, profile, item) for item in configured],
            )
            old = db.execute(
                "SELECT service FROM seen WHERE host=? AND profile=? ORDER BY service",
                (host, profile),
            )
            return [row[0] for row in old if row[0] not in configured]
    finally:
        db.close()


def forget(host, profile, state_dir=None):
    path = _state_path(state_dir)
    if not path.exists():
        return
    db = sqlite3.connect(path, timeout=5)
    try:
        with db:
            db.execute("PRAGMA secure_delete=ON")
            db.execute("DELETE FROM seen WHERE host=? AND profile=?", (host, profile))
    finally:
        db.close()
