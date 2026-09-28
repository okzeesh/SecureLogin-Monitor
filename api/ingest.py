"""Write a login attempt, run detection, and notify live dashboard clients."""

from datetime import datetime, timezone

from api.db import connect, normalize_ip_rows
from api.detection import run_detection
from api.live import broker


def record_login_event(
    username: str,
    source_ip: str,
    country: str | None,
    device: str | None,
    login_method: str,
    status: str,
    failure_reason: str | None,
) -> dict:
    event_time = datetime.now(timezone.utc)
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO login_events (
                event_time, username, source_ip, country, device,
                login_method, status, failure_reason
            ) VALUES (%s, %s, %s::inet, %s, %s, %s, %s, %s)
            RETURNING event_id, event_time, username, source_ip, country, device,
                      login_method, status, failure_reason
            """,
            (
                event_time,
                username,
                source_ip,
                country,
                device,
                login_method,
                status,
                failure_reason,
            ),
        ).fetchone()
        created = run_detection(conn)
        conn.commit()

    event = normalize_ip_rows([dict(row)])[0]
    broker.publish(
        {
            "type": "login_event",
            "event": event,
            "alerts_created": sum(created.values()),
        }
    )
    return event
