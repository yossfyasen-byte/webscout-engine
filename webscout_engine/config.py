"""Configuration, first-run setup, logging and scan history."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
import yaml
from pydantic import BaseModel, Field
import json
import logging
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
import sqlite3
from dataclasses import dataclass
from .core.models import ScanReport


# -------------------------------------------------------------------------
# from config.py
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# from config.py
# -------------------------------------------------------------------------

DEFAULT_USER_AGENT = "webscout_engine/1.0 (authorized security assessment)"


class UiSettings(BaseModel):
    no_color: bool = False
    ascii_only: bool = False
    arrow_keys: bool = True


class Settings(BaseModel):
    """User-facing settings persisted to YAML."""

    threads: int = 20
    timeout: float = 10.0
    rate: float = 25.0
    depth: int = 2
    ports: str = "top100"
    wordlist_tier: str = "small"
    extensions: list[str] = Field(default_factory=lambda: ["php", "html", "bak", "txt"])
    output_dir: str = ""
    formats: list[str] = Field(default_factory=lambda: ["json", "html", "csv", "sarif"])
    lab_mode: bool = False
    include_subdomains: bool = False
    verify_tls: bool = True
    max_requests: int = 20_000
    max_body: int = 262_144
    retries: int = 2
    user_agent: str = DEFAULT_USER_AGENT
    checks: list[str] = Field(default_factory=list)
    ui: UiSettings = Field(default_factory=UiSettings)


def home_dir() -> Path:
    override = os.environ.get("webscout_engine_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".webscout_engine"


def config_path() -> Path:
    return home_dir() / "config.yaml"


def reports_dir(settings: Settings | None = None) -> Path:
    if settings and settings.output_dir:
        return Path(settings.output_dir).expanduser()
    return home_dir() / "reports"


def history_path() -> Path:
    return home_dir() / "history.db"


def wordlist_dir() -> Path:
    return home_dir() / "wordlists"


def logs_dir() -> Path:
    return home_dir() / "logs"


def ensure_dirs() -> dict[str, Path]:
    """Create the user directory tree; safe to call repeatedly."""
    paths = {
        "home": home_dir(),
        "reports": reports_dir(),
        "wordlists": wordlist_dir(),
        "logs": logs_dir(),
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def default_settings() -> Settings:
    settings = Settings()
    settings.output_dir = str(reports_dir(settings))
    return settings


def load_settings(path: Path | None = None) -> Settings:
    """Load YAML over the built-in defaults; malformed files fall back safely."""
    target = path or config_path()
    settings = default_settings()
    if not target.exists():
        return settings
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return settings
    if not isinstance(raw, dict):
        return settings
    merged = _deep_merge(settings.model_dump(), raw)
    try:
        return Settings(**merged)
    except Exception:
        return settings


def save_settings(settings: Settings, path: Path | None = None) -> Path:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = settings.model_dump()
    target.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return target


def write_default_config(path: Path | None = None, force: bool = False) -> Path:
    target = path or config_path()
    if target.exists() and not force:
        return target
    return save_settings(default_settings(), target)


# -------------------------------------------------------------------------
# from logging_setup.py
# -------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key in ("module", "target", "check", "endpoint"):
            value = getattr(record, key, None)
            if value:
                payload[key] = value
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(verbose: bool = False, log_file: Path | None = None, quiet: bool = False) -> logging.Logger:
    root = logging.getLogger("webscout_engine")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.propagate = False

    if not quiet:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG if verbose else logging.WARNING)
        console.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        root.addHandler(console)

    target = log_file
    if target is None:
        try:
            logs_dir().mkdir(parents=True, exist_ok=True)
            target = logs_dir() / "webscout_engine.log"
        except OSError:
            target = None
    if target is not None:
        try:
            file_handler = RotatingFileHandler(target, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(JsonFormatter())
            root.addHandler(file_handler)
        except OSError:
            pass
    return root


# -------------------------------------------------------------------------
# from history.py
# -------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    target       TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    completed    INTEGER NOT NULL DEFAULT 0,
    interrupted  INTEGER NOT NULL DEFAULT 0,
    modules      TEXT NOT NULL DEFAULT '',
    findings     INTEGER NOT NULL DEFAULT 0,
    critical     INTEGER NOT NULL DEFAULT 0,
    high         INTEGER NOT NULL DEFAULT 0,
    medium       INTEGER NOT NULL DEFAULT 0,
    low          INTEGER NOT NULL DEFAULT 0,
    info         INTEGER NOT NULL DEFAULT 0,
    requests     INTEGER NOT NULL DEFAULT 0,
    duration     REAL NOT NULL DEFAULT 0,
    report_path  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
"""


@dataclass(slots=True)
class ScanSummary:
    scan_id: str
    target: str
    started_at: str
    finished_at: str
    completed: bool
    interrupted: bool
    modules: list[str]
    findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    requests: int
    duration: float
    report_path: str


class HistoryStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or history_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(str(self.path))
        self._connection.row_factory = sqlite3.Row
        self._connection.executescript(SCHEMA)
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> HistoryStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def record(self, report: ScanReport, report_path: str = "") -> None:
        counts = report.severity_counts or {}
        modules = ",".join(module.module for module in report.modules)
        self._connection.execute(
            """
            INSERT OR REPLACE INTO scans
            (scan_id, target, started_at, finished_at, completed, interrupted, modules,
             findings, critical, high, medium, low, info, requests, duration, report_path)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                report.scan_id,
                report.target,
                report.started_at.isoformat(),
                (report.finished_at or report.started_at).isoformat(),
                int(report.completed),
                int(report.interrupted),
                modules,
                len(report.findings),
                counts.get("critical", 0),
                counts.get("high", 0),
                counts.get("medium", 0),
                counts.get("low", 0),
                counts.get("info", 0),
                report.stats.requests,
                report.duration_seconds,
                report_path,
            ),
        )
        self._connection.commit()

    def list_scans(self, limit: int = 25) -> list[ScanSummary]:
        rows = self._connection.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            ScanSummary(
                scan_id=row["scan_id"],
                target=row["target"],
                started_at=row["started_at"],
                finished_at=row["finished_at"] or "",
                completed=bool(row["completed"]),
                interrupted=bool(row["interrupted"]),
                modules=[m for m in str(row["modules"]).split(",") if m],
                findings=row["findings"],
                critical=row["critical"],
                high=row["high"],
                medium=row["medium"],
                low=row["low"],
                info=row["info"],
                requests=row["requests"],
                duration=row["duration"],
                report_path=row["report_path"],
            )
            for row in rows
        ]

    def get(self, scan_id: str) -> dict | None:
        row = self._connection.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def count(self) -> int:
        row = self._connection.execute("SELECT COUNT(*) AS n FROM scans").fetchone()
        return int(row["n"]) if row else 0

    def to_json(self, limit: int = 25) -> str:
        return json.dumps([scan.__dict__ for scan in self.list_scans(limit)], default=str, indent=2)
