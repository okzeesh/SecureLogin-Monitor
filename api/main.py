"""SecureLogin Monitor API, live stream, staff portal, and dashboard."""

from contextlib import asynccontextmanager
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from api.db import connect, normalize_ip_rows
from api.live import broker, event_stream
from api.portal import router as portal_router

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(_app: FastAPI):
    import asyncio

    broker.bind_loop(asyncio.get_running_loop())
    yield


app = FastAPI(
    title="SecureLogin Monitor API",
    version="0.2.0",
    description="Read login events, receive live updates, and host the local staff portal.",
    lifespan=lifespan,
)
app.include_router(portal_router)


class LoginEvent(BaseModel):
    event_id: int
    event_time: datetime
    username: str
    source_ip: str
    country: str | None
    device: str | None
    login_method: str
    status: Literal["SUCCESS", "FAILED"]
    failure_reason: str | None


class SecurityAlert(BaseModel):
    alert_id: int
    alert_type: str
    severity: str
    source_ip: str | None
    username: str | None
    description: str
    status: str
    failed_attempt_count: int | None
    window_start: datetime | None
    window_end: datetime | None
    first_event_id: int | None
    last_event_id: int | None
    created_at: datetime
    updated_at: datetime


@app.get("/health")
def health() -> dict[str, str]:
    with connect() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "database": "connected"}


@app.get("/live")
async def live_updates() -> StreamingResponse:
    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/login-events", response_model=list[LoginEvent])
def list_login_events(
    response: Response,
    username: str | None = Query(default=None, max_length=100),
    status: Literal["SUCCESS", "FAILED"] | None = None,
    source_ip: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    if start_time and end_time and end_time < start_time:
        raise HTTPException(status_code=422, detail="end_time must be after start_time.")
    if source_ip is not None:
        try:
            ip_address(source_ip)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="source_ip must be a valid IP address.") from exc

    clauses: list[str] = []
    params: list[object] = []
    if username is not None:
        clauses.append("username = %s")
        params.append(username)
    if status is not None:
        clauses.append("status = %s")
        params.append(status)
    if source_ip is not None:
        clauses.append("source_ip = %s::inet")
        params.append(source_ip)
    if start_time is not None:
        clauses.append("event_time >= %s")
        params.append(start_time)
    if end_time is not None:
        clauses.append("event_time <= %s")
        params.append(end_time)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"""
        SELECT event_id, event_time, username, source_ip, country, device,
               login_method, status, failure_reason
        FROM login_events
        {where}
        ORDER BY event_time DESC, event_id DESC
        LIMIT %s OFFSET %s
    """
    params.extend((limit, offset))

    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
        count_query = f"SELECT COUNT(*) AS total FROM login_events {where}"
        total = conn.execute(count_query, params[:-2]).fetchone()["total"]

    response.headers["X-Total-Count"] = str(total)
    return normalize_ip_rows(rows)


@app.get("/security-alerts", response_model=list[SecurityAlert])
def list_security_alerts(
    response: Response,
    username: str | None = Query(default=None, max_length=100),
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"] | None = None,
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    clauses: list[str] = []
    params: list[object] = []
    if username is not None:
        clauses.append("username = %s")
        params.append(username)
    if status is not None:
        clauses.append("status = %s")
        params.append(status)
    if severity is not None:
        clauses.append("severity = %s")
        params.append(severity)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"""
        SELECT alert_id, alert_type, severity, source_ip, username, description,
               status, failed_attempt_count, window_start, window_end,
               first_event_id, last_event_id, created_at, updated_at
        FROM security_alerts
        {where}
        ORDER BY created_at DESC, alert_id DESC
        LIMIT %s OFFSET %s
    """
    params.extend((limit, offset))

    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
        count_query = f"SELECT COUNT(*) AS total FROM security_alerts {where}"
        total = conn.execute(count_query, params[:-2]).fetchone()["total"]

    response.headers["X-Total-Count"] = str(total)
    return normalize_ip_rows(rows)


@app.get("/summary")
def dashboard_summary() -> dict:
    with connect() as conn:
        totals = conn.execute("""
            SELECT COUNT(*) FILTER (WHERE event_time >= NOW() - INTERVAL '24 hours') AS events_24h,
                   COUNT(*) FILTER (WHERE event_time >= NOW() - INTERVAL '24 hours' AND status = 'SUCCESS') AS successes_24h,
                   COUNT(*) FILTER (WHERE event_time >= NOW() - INTERVAL '24 hours' AND status = 'FAILED') AS failures_24h,
                   COUNT(DISTINCT username) FILTER (WHERE event_time >= NOW() - INTERVAL '24 hours') AS users_24h
            FROM login_events
        """).fetchone()
        open_alerts = conn.execute(
            "SELECT COUNT(*) AS total FROM security_alerts WHERE status = 'OPEN'"
        ).fetchone()["total"]
        hourly = conn.execute("""
            SELECT date_trunc('hour', event_time) AS hour,
                   COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE status = 'FAILED') AS failures
            FROM login_events
            WHERE event_time >= NOW() - INTERVAL '24 hours'
            GROUP BY hour ORDER BY hour
        """).fetchall()
        top_failed_ips = conn.execute("""
            SELECT source_ip, COUNT(*) AS failures
            FROM login_events
            WHERE status = 'FAILED' AND event_time >= NOW() - INTERVAL '24 hours'
            GROUP BY source_ip ORDER BY failures DESC LIMIT 6
        """).fetchall()
        countries = conn.execute("""
            SELECT COALESCE(country, 'Unknown') AS country, COUNT(*) AS total
            FROM login_events
            WHERE event_time >= NOW() - INTERVAL '24 hours'
            GROUP BY country ORDER BY total DESC LIMIT 6
        """).fetchall()
        severity = conn.execute("""
            SELECT severity, COUNT(*) AS total FROM security_alerts
            WHERE status = 'OPEN' GROUP BY severity
        """).fetchall()

    return {
        **totals,
        "open_alerts": open_alerts,
        "hourly": hourly,
        "top_failed_ips": normalize_ip_rows(top_failed_ips),
        "countries": countries,
        "open_alerts_by_severity": severity,
    }


app.mount("/portal", StaticFiles(directory=ROOT / "portal", html=True), name="portal")
app.mount("/", StaticFiles(directory=ROOT / "dashboard", html=True), name="dashboard")
