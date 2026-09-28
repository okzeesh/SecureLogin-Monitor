"""PostgreSQL connection helpers. Credentials stay in environment variables."""

from ipaddress import IPv4Address, IPv6Address
import os

import psycopg
from fastapi import HTTPException
from psycopg.rows import dict_row


def connect() -> psycopg.Connection:
    required = ("DB_NAME", "DB_USER", "DB_PASSWORD")
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise HTTPException(
            status_code=503,
            detail="Database configuration is incomplete; set DB_NAME, DB_USER, and DB_PASSWORD.",
        )

    try:
        return psycopg.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            dbname=os.environ["DB_NAME"],
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            connect_timeout=5,
            row_factory=dict_row,
        )
    except (psycopg.Error, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Could not connect to PostgreSQL.") from exc


def normalize_ip_rows(rows: list[dict]) -> list[dict]:
    for row in rows:
        value = row.get("source_ip")
        if isinstance(value, (IPv4Address, IPv6Address)):
            row["source_ip"] = str(value)
        elif value is not None:
            row["source_ip"] = str(value).split("/")[0]
    return rows
