"""Local staff intranet login. Each attempt is stored as a login_event."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from api.db import connect
from api.ingest import record_login_event

router = APIRouter(tags=["staff-portal"])

ACCOUNTS = {
    "alice.rahman": {
        "password": "Welcome123!",
        "mfa": "654321",
        "require_mfa": True,
        "disabled": False,
    },
    "bob.hassan": {
        "password": "Welcome123!",
        "mfa": None,
        "require_mfa": False,
        "disabled": False,
    },
    "admin": {
        "password": "Admin#2026",
        "mfa": None,
        "require_mfa": False,
        "disabled": False,
    },
    "finance": {
        "password": "Finance#2026",
        "mfa": None,
        "require_mfa": False,
        "disabled": False,
    },
}

COUNTRIES = {
    "United Arab Emirates",
    "United States",
    "United Kingdom",
    "India",
    "Germany",
    "Singapore",
}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)
    mfa_code: str | None = Field(default=None, max_length=12)
    country: str = "United Arab Emirates"
    use_mfa: bool = False


class LoginResponse(BaseModel):
    ok: bool
    message: str
    event_id: int
    status: Literal["SUCCESS", "FAILED"]
    failure_reason: str | None = None


def device_from_user_agent(user_agent: str | None) -> str:
    ua = (user_agent or "").lower()
    if "iphone" in ua:
        return "iPhone"
    if "android" in ua:
        return "Android-Phone"
    if "mac os" in ua or "macintosh" in ua:
        return "MacBook-Pro"
    if "windows" in ua:
        return "Windows-Laptop"
    if "linux" in ua:
        return "Linux-Workstation"
    return "Web-Browser"


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    host = request.client.host if request.client else "127.0.0.1"
    if host in {"::1", "localhost"}:
        return "127.0.0.1"
    return host


def recent_failure_count(username: str) -> int:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM login_events
            WHERE username = %s
              AND status = 'FAILED'
              AND event_time >= NOW() - INTERVAL '5 minutes'
            """,
            (username,),
        ).fetchone()
    return int(row["total"])


def evaluate_login(payload: LoginRequest) -> tuple[str, str | None, str]:
    username = payload.username.strip()
    account = ACCOUNTS.get(username)
    method = "PASSWORD_MFA" if payload.use_mfa or payload.mfa_code else "PASSWORD"

    if account is None:
        return "FAILED", "INVALID_USERNAME", method
    if account["disabled"]:
        return "FAILED", "ACCOUNT_DISABLED", method
    if recent_failure_count(username) >= 8:
        return "FAILED", "ACCOUNT_LOCKED", method
    if payload.password != account["password"]:
        return "FAILED", "INVALID_PASSWORD", method
    if account["require_mfa"] or payload.use_mfa:
        method = "PASSWORD_MFA"
        if payload.mfa_code != account["mfa"]:
            return "FAILED", "MFA_FAILED", method
    return "SUCCESS", None, method


@router.post("/auth/login", response_model=LoginResponse)
def staff_login(payload: LoginRequest, request: Request) -> LoginResponse:
    if payload.country not in COUNTRIES:
        raise HTTPException(status_code=422, detail="Choose a supported country.")

    username = payload.username.strip()
    status, failure_reason, method = evaluate_login(payload)
    event = record_login_event(
        username=username,
        source_ip=client_ip(request),
        country=payload.country,
        device=device_from_user_agent(request.headers.get("user-agent")),
        login_method=method,
        status=status,
        failure_reason=failure_reason,
    )
    if status == "SUCCESS":
        return LoginResponse(
            ok=True,
            message="Signed in. Open the security dashboard to see this event live.",
            event_id=event["event_id"],
            status=status,
        )
    readable = (failure_reason or "UNKNOWN").replace("_", " ").title()
    return LoginResponse(
        ok=False,
        message=f"Sign-in failed: {readable}.",
        event_id=event["event_id"],
        status=status,
        failure_reason=failure_reason,
    )
