"""Throwaway SQLite storage: the fake app's data (app.db) and the learner's progress (lab.db)."""

import os
import secrets
import shutil
import sqlite3
import threading
import time
from functools import cache
from pathlib import Path

from werkzeug.security import generate_password_hash

from .challenges import FLAGS

LEARNER = ("alice", "alice-demo")

APP_SCHEMA = """
DROP TABLE IF EXISTS credit_log;
DROP TABLE IF EXISTS vouchers;
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS invoices;
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    credit_cents INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE invoices (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    customer TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    status TEXT NOT NULL,
    memo TEXT NOT NULL DEFAULT ''
);
CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE vouchers (
    code TEXT PRIMARY KEY,
    cents INTEGER NOT NULL,
    redeemed_by INTEGER REFERENCES users(id)
);
CREATE TABLE credit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    voucher TEXT NOT NULL,
    cents INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

LAB_SCHEMA = """
CREATE TABLE IF NOT EXISTS progress (
    id TEXT PRIMARY KEY,
    solved_at REAL,
    fixed_at REAL,
    announced INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

INVOICES = [
    (1001, 1, "Acme Robotics", 124000, "paid", "Quarterly maintenance contract."),
    (1002, 1, "O'Brien & Sons", 56050, "due", "Net 30. Ask for Sean."),
    (1003, 1, "Northside Bakery", 8900, "overdue", "Second reminder sent."),
    (2001, 2, "Harbor Freight Lines", 1840000, "due", f"Confidential: 22% off-contract discount. {FLAGS['idor']}"),
    (2002, 2, "Lumen Dental Group", 312500, "paid", "Paid by wire."),
    (3001, 3, "Quillbook Payroll", 990000, "paid", "Internal transfer."),
]

NOTES = [
    (3, "Welcome to the team board, Alice. Everyone in the workspace can read what you post here."),
    (2, "Reminder: the billing keys are served at /internal/keys. That address only answers the app server itself."),
    (3, "Exports are plain text files, invoice-1001.txt and so on. Payroll lives next door in private/, hands off."),
]

# One-time vouchers. The partner still knows QB-WELCOME-10; it withdrew QB-SPRING-25 (see app.VOUCHER_PARTNER).
VOUCHERS = [("QB-WELCOME-10", 1000), ("QB-SPRING-25", 2500)]


@cache
def _users():
    """Seed users. Hashing is slow on purpose, so do it once per process."""
    people = [
        (1, LEARNER[0], LEARNER[1], "Alice Moreau", "alice@quillbook.test", "user", 2500),
        (2, "bob", secrets.token_urlsafe(12), "Bob Ferreira", "bob@quillbook.test", "user", 0),
        (3, "carol", secrets.token_urlsafe(12), "Carol Whitfield", "carol@quillbook.test", "admin", 0),
    ]
    return [(i, name, generate_password_hash(pw), *rest) for i, name, pw, *rest in people]


def connect(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


_seeding = threading.Lock()  # the web server is threaded: two resets at once must not interleave


def seed_app(data_dir: Path):
    """(Re)create the fake app's tables and files with fresh data."""
    with _seeding:
        # Build the new database beside the old one and swap it in, so a request running during
        # a reset sees the whole old data or the whole new data, never a half-dropped schema.
        fresh = data_dir / "app.db.new"
        fresh.unlink(missing_ok=True)
        conn = connect(fresh)
        with conn:
            conn.executescript(APP_SCHEMA)
            conn.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)", _users())
            conn.executemany("INSERT INTO invoices VALUES (?, ?, ?, ?, ?, ?)", INVOICES)
            conn.executemany("INSERT INTO notes (author_id, body) VALUES (?, ?)", NOTES)
            conn.executemany("INSERT INTO vouchers (code, cents) VALUES (?, ?)", VOUCHERS)
        conn.close()
        os.replace(fresh, data_dir / "app.db")
        _seed_files(data_dir)


def _seed_files(data_dir: Path):
    files = data_dir / "files"
    shutil.rmtree(files, ignore_errors=True)
    (files / "exports").mkdir(parents=True)
    (files / "private").mkdir()
    for number, owner, customer, cents, status, memo in INVOICES:
        if owner == 1:
            text = f"Invoice {number}\nCustomer: {customer}\nAmount: ${cents / 100:,.2f}\nStatus: {status}\n{memo}\n"
            (files / "exports" / f"invoice-{number}.txt").write_text(text, encoding="utf-8")
    (files / "private" / "payroll-2026.txt").write_text(
        f"Payroll 2026 (private)\nCarol Whitfield  9,900.00\nBob Ferreira     6,150.00\n{FLAGS['path_traversal']}\n",
        encoding="utf-8",
    )


def init(data_dir: Path):
    """Create the data directory on first use. Returns the persisted session secret."""
    data_dir.mkdir(parents=True, exist_ok=True)
    lab = connect(data_dir / "lab.db")
    with lab:
        lab.executescript(LAB_SCHEMA)
        lab.execute("INSERT OR IGNORE INTO meta VALUES ('secret', ?)", (secrets.token_hex(32),))
    secret = lab.execute("SELECT value FROM meta WHERE key = 'secret'").fetchone()[0]
    lab.close()
    if not (data_dir / "app.db").exists() or not _has_table(data_dir / "app.db", "credit_log"):
        seed_app(data_dir)  # first start, or data from a version without the race condition challenge
    return secret


def _has_table(path, name):
    conn = connect(path)
    try:
        return (
            conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone()
            is not None
        )
    finally:
        conn.close()


def award(lab, challenge_id):
    """Record a captured flag. Returns True the first time."""
    with lab:
        cur = lab.execute(
            "INSERT INTO progress (id, solved_at) VALUES (?, ?) "
            "ON CONFLICT(id) DO UPDATE SET solved_at = excluded.solved_at WHERE solved_at IS NULL",
            (challenge_id, time.time()),
        )
    return cur.rowcount == 1


def set_fixed(lab, challenge_id, fixed):
    with lab:
        lab.execute(
            "INSERT INTO progress (id, fixed_at) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET fixed_at = excluded.fixed_at",
            (challenge_id, time.time() if fixed else None),
        )


def progress(lab):
    return {row["id"]: row for row in lab.execute("SELECT * FROM progress")}


def pop_fresh(lab):
    """Challenge ids captured since the last page render, for the 'flag captured' banner."""
    with lab:
        ids = [r[0] for r in lab.execute("SELECT id FROM progress WHERE solved_at IS NOT NULL AND announced = 0")]
        lab.execute("UPDATE progress SET announced = 1 WHERE solved_at IS NOT NULL")
    return ids


def reset_progress(lab):
    with lab:
        lab.execute("DELETE FROM progress")
