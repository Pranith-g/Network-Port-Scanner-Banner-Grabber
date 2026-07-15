from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from scanner import ScanResult


DB_PATH = Path(__file__).resolve().parent / "scanner_app.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                target_host TEXT NOT NULL,
                resolved_ip TEXT NOT NULL,
                start_port INTEGER NOT NULL,
                end_port INTEGER NOT NULL,
                timeout REAL NOT NULL,
                grab_banner INTEGER NOT NULL,
                workers INTEGER NOT NULL,
                duration_seconds REAL NOT NULL,
                open_ports INTEGER NOT NULL,
                banners_found INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                results_json TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    password_salt = salt or os.urandom(16).hex()
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        password_salt.encode("utf-8"),
        100_000,
    ).hex()
    return password_hash, password_salt


def create_user(username: str, password: str) -> None:
    password_hash, password_salt = hash_password(password)
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if existing is not None:
            raise ValueError("That username already exists. Please choose another one.")
        connection.execute(
            """
            INSERT INTO users (username, password_hash, password_salt, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (username, password_hash, password_salt, datetime.utcnow().isoformat()),
        )


def verify_user_credentials(username: str, password: str) -> dict[str, str | int] | None:
    with get_connection() as connection:
        user = connection.execute(
            """
            SELECT id, username, password_hash, password_salt
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
        if user is None:
            return None

        candidate_hash, _ = hash_password(password, user["password_salt"])
        if candidate_hash != user["password_hash"]:
            return None

        return {"id": user["id"], "username": user["username"]}


def create_scan_record(
    user_id: int,
    target_host: str,
    resolved_ip: str,
    start_port: int,
    end_port: int,
    timeout: float,
    grab_banner: bool,
    workers: int,
    duration_seconds: float,
    results: list[ScanResult],
) -> None:
    open_ports = sum(1 for result in results if result.is_open)
    banners_found = sum(1 for result in results if result.banner)
    payload = [result.to_dict() for result in results]

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO scans (
                user_id, target_host, resolved_ip, start_port, end_port, timeout,
                grab_banner, workers, duration_seconds, open_ports, banners_found,
                created_at, results_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                target_host,
                resolved_ip,
                start_port,
                end_port,
                timeout,
                1 if grab_banner else 0,
                workers,
                duration_seconds,
                open_ports,
                banners_found,
                datetime.utcnow().isoformat(),
                json.dumps(payload),
            ),
        )


def fetch_scan_history(user_id: int) -> list[dict[str, str | int | float]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                target_host,
                resolved_ip,
                start_port,
                end_port,
                timeout,
                workers,
                open_ports,
                banners_found,
                duration_seconds,
                created_at
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,),
        ).fetchall()

    history: list[dict[str, str | int | float]] = []
    for row in rows:
        history.append(
            {
                "Scan ID": row["id"],
                "Target": row["target_host"],
                "Resolved IP": row["resolved_ip"],
                "Ports": f'{row["start_port"]}-{row["end_port"]}',
                "Timeout": row["timeout"],
                "Threads": row["workers"],
                "Open Ports": row["open_ports"],
                "Banners": row["banners_found"],
                "Duration (s)": round(row["duration_seconds"], 2),
                "Created At": row["created_at"].replace("T", " ")[:19],
            }
        )
    return history
