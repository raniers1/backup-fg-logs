#!/usr/bin/env python3
"""
backup_api.py (auth version)

FastAPI service that reads the SQLite DB created by backup_fg and exposes endpoints:
  - GET /backups
  - GET /backups/{id}
  - GET /health   <-- agora sempre retorna HTTP 200

This version **requires a Bearer token** for the backups endpoints.
Valid tokens are read from the environment variable `APP_TOKENS` as a
comma-separated list:

  export APP_TOKENS="token1,token2"

Requests must include header:
  Authorization: Bearer <token>

If APP_TOKENS is not set or empty the app will raise at startup.
"""
from __future__ import annotations

import os
import sqlite3
import logging
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import JSONResponse
from pydantic import BaseModel

LOG = logging.getLogger("backup_api")
logging.basicConfig(level=logging.INFO)

DB_PATH = os.environ.get("DB_PATH", "/var/lib/backup_fg/backup_records.db")
APP_TOKENS_RAW = os.environ.get("APP_TOKENS", "")
# parse tokens into a set for quick validation
ALLOWED_TOKENS = {t.strip() for t in APP_TOKENS_RAW.split(",") if t.strip()}

if not ALLOWED_TOKENS:
    # fail-fast: app is intentionally misconfigured without tokens
    raise RuntimeError("APP_TOKENS environment variable must be set to at least one token")

app = FastAPI(title="Backup FG API (auth)", version="1.0")

security = HTTPBearer(auto_error=False)


class BackupOut(BaseModel):
    filename: str
    s3_url: Optional[str] = None
    backup_date: Optional[str] = None


def validate_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    """
    Dependency that enforces a Bearer token and validates it against ALLOWED_TOKENS.
    Raises 401 if missing/invalid.
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    if credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid auth scheme", headers={"WWW-Authenticate": "Bearer"})
    token = credentials.credentials
    if token not in ALLOWED_TOKENS:
        raise HTTPException(status_code=401, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})
    return token


def get_db_connection():
    """Yield a sqlite3 connection for the request; caller must close."""
    if not os.path.exists(DB_PATH):
        raise HTTPException(status_code=500, detail=f"DB not found at {DB_PATH}")
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


@app.get("/backups", response_model=List[BackupOut])
def list_backups(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None),
    token: str = Depends(validate_token),
    conn: sqlite3.Connection = Depends(get_db_connection),
):
    """
    List backups. Optional filtering by status.
    Returns filename, s3_url, backup_date.
    """
    params = []
    sql = "SELECT filename, s3_url, backup_date FROM backups"
    if status:
        sql += " WHERE status = ?"
        params.append(status)
    sql += " ORDER BY uploaded_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    cur = conn.execute(sql, params)
    rows = cur.fetchall()
    result = []
    for r in rows:
        result.append(
            {
                "filename": r["filename"],
                "s3_url": r["s3_url"],
                "backup_date": r["backup_date"],
            }
        )
    return result


@app.get("/backups/{record_id}", response_model=BackupOut)
def get_backup(record_id: int, token: str = Depends(validate_token), conn: sqlite3.Connection = Depends(get_db_connection)):
    cur = conn.execute("SELECT filename, s3_url, backup_date FROM backups WHERE id = ?", (record_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Backup record not found")
    return {"filename": row["filename"], "s3_url": row["s3_url"], "backup_date": row["backup_date"]}


@app.get("/health")
def health():
    """
    Health endpoint for probes/monitoring.

    - Does NOT require authentication so load-balancers/monitors can probe it.
    - Returns HTTP 200 unconditionally with a minimal payload {"status":"ok"}.
    """
    return JSONResponse(status_code=200, content={"status": "ok"})
