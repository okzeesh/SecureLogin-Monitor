"""Rule-based detection for synthetic and real login event patterns."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import math

import psycopg


COUNTRY_COORDINATES = {
    "UAE": (24.4539, 54.3773),
    "United Arab Emirates": (24.4539, 54.3773),
    "United States": (38.9072, -77.0369),
    "United Kingdom": (51.5072, -0.1276),
    "India": (28.6139, 77.2090),
    "Germany": (52.5200, 13.4050),
    "Singapore": (1.3521, 103.8198),
}


def _alert(
    alert_type: str,
    severity: str,
    username: str | None,
    source_ip: str | None,
    description: str,
    first_event_id: int,
    last_event_id: int,
    window_start: datetime,
    window_end: datetime,
    failed_attempt_count: int | None = None,
) -> dict:
    identity = "|".join((alert_type, username or "", source_ip or "", str(first_event_id), str(last_event_id)))
    return {
        "alert_type": alert_type,
        "severity": severity,
        "username": username,
        "source_ip": source_ip,
        "description": description,
        "failed_attempt_count": failed_attempt_count,
        "window_start": window_start,
        "window_end": window_end,
        "first_event_id": first_event_id,
        "last_event_id": last_event_id,
        "dedupe_key": sha256(identity.encode("utf-8")).hexdigest(),
    }


def _haversine_km(first: tuple[float, float], second: tuple[float, float]) -> float:
    earth_radius_km = 6371.0
    lat1, lon1 = map(math.radians, first)
    lat2, lon2 = map(math.radians, second)
    delta_lat, delta_lon = lat2 - lat1, lon2 - lon1
    value = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    )
    return earth_radius_km * 2 * math.atan2(math.sqrt(value), math.sqrt(1 - value))


def detect_brute_force(conn: psycopg.Connection) -> list[dict]:
    rows = conn.execute("""
        SELECT username, source_ip, date_bin(INTERVAL '5 minutes', event_time,
               TIMESTAMPTZ '2000-01-01 00:00:00+00') AS window_start,
               MIN(event_time) AS first_time, MAX(event_time) AS last_time,
               COUNT(*) AS attempts,
               (ARRAY_AGG(event_id ORDER BY event_time, event_id))[1] AS first_id,
               (ARRAY_AGG(event_id ORDER BY event_time DESC, event_id DESC))[1] AS last_id
        FROM login_events
        WHERE status = 'FAILED' AND event_time >= NOW() - INTERVAL '30 days'
        GROUP BY username, source_ip, window_start
        HAVING COUNT(*) >= 5
    """).fetchall()
    return [
        _alert(
            "BRUTE_FORCE", "HIGH" if row["attempts"] >= 10 else "MEDIUM",
            row["username"], str(row["source_ip"]),
            f"{row['attempts']} failed login attempts for {row['username']} from {row['source_ip']} in five minutes.",
            row["first_id"], row["last_id"], row["first_time"], row["last_time"], row["attempts"],
        )
        for row in rows
    ]


def detect_suspicious_ips(conn: psycopg.Connection) -> list[dict]:
    rows = conn.execute("""
        SELECT source_ip, date_bin(INTERVAL '10 minutes', event_time,
               TIMESTAMPTZ '2000-01-01 00:00:00+00') AS window_start,
               COUNT(DISTINCT username) AS account_count,
               COUNT(*) FILTER (WHERE status = 'FAILED') AS failures,
               MIN(event_time) AS first_time, MAX(event_time) AS last_time,
               (ARRAY_AGG(event_id ORDER BY event_time, event_id))[1] AS first_id,
               (ARRAY_AGG(event_id ORDER BY event_time DESC, event_id DESC))[1] AS last_id
        FROM login_events
        WHERE event_time >= NOW() - INTERVAL '30 days'
        GROUP BY source_ip, window_start
        HAVING COUNT(DISTINCT username) >= 5
           AND COUNT(*) FILTER (WHERE status = 'FAILED') >= 8
    """).fetchall()
    return [
        _alert(
            "SUSPICIOUS_IP", "HIGH", None, str(row["source_ip"]),
            f"Source IP {row['source_ip']} had {row['failures']} failures across {row['account_count']} accounts in ten minutes.",
            row["first_id"], row["last_id"], row["first_time"], row["last_time"], row["failures"],
        )
        for row in rows
    ]


def detect_new_devices(conn: psycopg.Connection) -> list[dict]:
    rows = conn.execute("""
        SELECT e.event_id, e.event_time, e.username, e.source_ip, e.device
        FROM login_events e
        WHERE e.status = 'SUCCESS' AND e.device IS NOT NULL
          AND e.event_time >= NOW() - INTERVAL '30 days'
          AND EXISTS (
              SELECT 1 FROM login_events prior
              WHERE prior.username = e.username AND prior.status = 'SUCCESS'
                AND prior.device IS NOT NULL AND prior.event_time < e.event_time
          )
          AND NOT EXISTS (
              SELECT 1 FROM login_events same_device
              WHERE same_device.username = e.username AND same_device.device = e.device
                AND same_device.status = 'SUCCESS' AND same_device.event_time < e.event_time
          )
        ORDER BY e.event_time
    """).fetchall()
    return [
        _alert(
            "NEW_DEVICE", "MEDIUM", row["username"], str(row["source_ip"]),
            f"Successful login for {row['username']} used a previously unseen device: {row['device']}.",
            row["event_id"], row["event_id"], row["event_time"], row["event_time"],
        )
        for row in rows
    ]


def detect_impossible_travel(conn: psycopg.Connection) -> list[dict]:
    rows = conn.execute("""
        SELECT event_id, event_time, username, source_ip, country
        FROM login_events
        WHERE status = 'SUCCESS' AND country IS NOT NULL
          AND event_time >= NOW() - INTERVAL '30 days'
        ORDER BY username, event_time, event_id
    """).fetchall()

    by_user: dict[str, list[dict]] = {}
    for row in rows:
        by_user.setdefault(row["username"], []).append(row)

    alerts = []
    for username, events in by_user.items():
        for first, second in zip(events, events[1:]):
            first_location = COUNTRY_COORDINATES.get(first["country"])
            second_location = COUNTRY_COORDINATES.get(second["country"])
            elapsed_hours = (second["event_time"] - first["event_time"]).total_seconds() / 3600
            if not first_location or not second_location or elapsed_hours <= 0 or elapsed_hours > 12:
                continue
            distance = _haversine_km(first_location, second_location)
            speed = distance / elapsed_hours
            if first["country"] != second["country"] and speed >= 900:
                alerts.append(_alert(
                    "IMPOSSIBLE_TRAVEL", "CRITICAL", username, str(second["source_ip"]),
                    f"{username} logged in from {first['country']} and {second['country']} only "
                    f"{elapsed_hours * 60:.1f} minutes apart (about {speed:,.0f} km/h implied).",
                    first["event_id"], second["event_id"], first["event_time"], second["event_time"],
                ))
    return alerts


def detect_abnormal_frequency(conn: psycopg.Connection) -> list[dict]:
    rows = conn.execute("""
        SELECT username, date_bin(INTERVAL '1 minute', event_time,
               TIMESTAMPTZ '2000-01-01 00:00:00+00') AS window_start,
               COUNT(*) AS attempts, MIN(event_time) AS first_time,
               MAX(event_time) AS last_time,
               (ARRAY_AGG(event_id ORDER BY event_time, event_id))[1] AS first_id,
               (ARRAY_AGG(event_id ORDER BY event_time DESC, event_id DESC))[1] AS last_id
        FROM login_events
        WHERE event_time >= NOW() - INTERVAL '30 days'
        GROUP BY username, window_start
        HAVING COUNT(*) >= 10
    """).fetchall()
    return [
        _alert(
            "ABNORMAL_FREQUENCY", "HIGH", row["username"], None,
            f"{row['username']} generated {row['attempts']} login events in one minute.",
            row["first_id"], row["last_id"], row["first_time"], row["last_time"],
        )
        for row in rows
    ]


DETECTION_RULES = (
    detect_brute_force,
    detect_suspicious_ips,
    detect_new_devices,
    detect_impossible_travel,
    detect_abnormal_frequency,
)


def run_detection(conn: psycopg.Connection) -> dict[str, int]:
    """Find rule matches and insert only alerts not created by earlier runs."""
    summary: dict[str, int] = {}
    for rule in DETECTION_RULES:
        candidates = rule(conn)
        created = 0
        for candidate in candidates:
            inserted = conn.execute("""
                INSERT INTO security_alerts (
                    alert_type, severity, source_ip, username, description,
                    failed_attempt_count, window_start, window_end,
                    first_event_id, last_event_id, dedupe_key
                ) VALUES (
                    %(alert_type)s, %(severity)s, %(source_ip)s::inet, %(username)s,
                    %(description)s, %(failed_attempt_count)s, %(window_start)s,
                    %(window_end)s, %(first_event_id)s, %(last_event_id)s,
                    %(dedupe_key)s
                ) ON CONFLICT (dedupe_key) DO NOTHING
                RETURNING alert_id
            """, candidate).fetchone()
            created += int(inserted is not None)
        summary[rule.__name__] = created
    return summary
