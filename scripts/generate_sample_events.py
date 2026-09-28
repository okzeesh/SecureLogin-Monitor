"""Generate synthetic login events for SecureLogin Monitor's V1 schema."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import os
import random

USERS = [
    "alice.rahman", "bob.hassan", "carol.khan", "david.ali", "eve.noor",
    "frank.saeed", "grace.malik", "hassan.omar", "iman.yousef", "james.reed",
    "karen.wood", "lee.chen", "maya.patel", "nora.smith", "omar.farouk",
    "priya.shah", "qasim.abbas", "rana.haddad", "sam.taylor", "tariq.amin",
    "uma.nair", "victor.lee", "wendy.clark", "xavier.martin", "yara.saleh",
    "zain.mirza", "service.reports", "service.backup", "admin", "finance",
]
COUNTRIES = [
    "United Arab Emirates", "United States", "United Kingdom", "India",
    "Germany", "Singapore", "Unknown",
]
DEVICES = [
    "Windows-Laptop", "MacBook-Pro", "iPhone", "Android-Phone",
    "Linux-Workstation", "Office-Desktop",
]
METHODS = ["PASSWORD", "PASSWORD_MFA", "SSO", "CERTIFICATE", "API_KEY"]
FAILURE_REASONS = [
    "INVALID_PASSWORD", "INVALID_USERNAME", "MFA_FAILED", "ACCOUNT_LOCKED",
    "ACCOUNT_DISABLED", "EXPIRED_CREDENTIALS",
]

INSERT_SQL = """
    INSERT INTO login_events (
        event_time, username, source_ip, country, device,
        login_method, status, failure_reason
    ) VALUES (%s, %s, %s::inet, %s, %s, %s, %s, %s)
"""


def make_event(
    event_time: datetime,
    username: str,
    source_ip: str,
    country: str | None,
    device: str | None,
    login_method: str,
    status: str,
    failure_reason: str | None = None,
) -> tuple:
    return (
        event_time, username, source_ip, country, device,
        login_method, status, failure_reason,
    )


def generate_events(count: int, seed: int) -> list[tuple]:
    """Create ordinary activity plus embedded, recognizable attack patterns."""
    pattern_count = 30 + 35 + 2 + 2 + 20
    if count < pattern_count:
        raise ValueError(f"count must be at least {pattern_count} to include all scenarios")

    rng = random.Random(seed)
    profile_rng = random.Random(seed ^ 0x5EC0)
    home_countries = {user: profile_rng.choice(COUNTRIES[:-1]) for user in USERS}
    home_devices = {user: profile_rng.choice(DEVICES) for user in USERS}
    # Keep the deliberately planted scenarios geographically coherent.
    home_countries.update({
        "alice.rahman": "United Arab Emirates",
        "bob.hassan": "United Arab Emirates",
        "maya.patel": "United Arab Emirates",
        "service.reports": "United Arab Emirates",
    })
    home_devices.update({
        "alice.rahman": "Alice-Laptop",
        "bob.hassan": "Bob-Laptop",
        "maya.patel": "Maya-Laptop",
        "service.reports": "Reports-Server",
    })
    now = datetime.now(timezone.utc).replace(microsecond=0)
    events: list[tuple] = []

    # Background traffic: mostly successful events, with realistic isolated failures.
    for _ in range(count - pattern_count):
        is_failure = rng.random() < 0.13
        status = "FAILED" if is_failure else "SUCCESS"
        username = rng.choice(USERS)
        events.append(make_event(
            # Keep background traffic before today's hand-planted examples so
            # random events cannot accidentally extend those attack sequences.
            now - timedelta(seconds=rng.randrange(24 * 60 * 60, 30 * 24 * 60 * 60)),
            username,
            f"192.0.2.{rng.randint(1, 254)}",
            home_countries[username] if rng.random() > 0.04 else None,
            (rng.choice(DEVICES) if rng.random() < 0.002 else home_devices[username])
            if rng.random() > 0.06 else None,
            rng.choice(METHODS),
            status,
            rng.choice(FAILURE_REASONS) if is_failure else None,
        ))

    # Brute-force burst against one account from one source IP.
    burst_start = now - timedelta(minutes=10)
    for index in range(30):
        events.append(make_event(
            burst_start + timedelta(seconds=index * 8), "admin", "203.0.113.77",
            "Unknown", "Unknown-Device", "PASSWORD", "FAILED", "INVALID_PASSWORD",
        ))

    # Password spraying: one source IP attempts many accounts.
    spray_start = now - timedelta(minutes=5)
    for index in range(35):
        events.append(make_event(
            spray_start + timedelta(seconds=index * 6), USERS[index % 25],
            "203.0.113.88", "Unknown", "Unknown-Device", "PASSWORD", "FAILED",
            "INVALID_PASSWORD",
        ))

    # A baseline device followed by an unfamiliar device for the same account.
    events.extend([
        make_event(now - timedelta(days=20), "maya.patel", "192.0.2.42",
                   "United Arab Emirates", "Maya-Laptop", "PASSWORD_MFA", "SUCCESS"),
        make_event(now - timedelta(minutes=4), "maya.patel", "198.51.100.42",
                   "United Arab Emirates", "Maya-Unknown-Device", "PASSWORD_MFA", "SUCCESS"),
    ])

    # Two successful logins from distant countries less than a minute apart.
    events.extend([
        make_event(now - timedelta(minutes=12), "bob.hassan", "192.0.2.57",
                   "United Arab Emirates", "Bob-Laptop", "PASSWORD_MFA", "SUCCESS"),
        make_event(now - timedelta(minutes=11, seconds=20), "bob.hassan", "198.51.100.57",
                   "United States", "Bob-Unknown", "PASSWORD_MFA", "SUCCESS"),
    ])

    # High volume of successful authentication events in a short window.
    frequency_start = now - timedelta(minutes=2)
    for index in range(20):
        events.append(make_event(
            frequency_start + timedelta(seconds=index * 5), "service.reports",
            "192.0.2.90", "United Arab Emirates", "Reports-Server", "API_KEY", "SUCCESS",
        ))

    rng.shuffle(events)
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=5000, help="number of events to insert (default: 5000)")
    parser.add_argument("--seed", type=int, default=20260928, help="random seed for reproducible data")
    parser.add_argument("--dry-run", action="store_true", help="generate and summarize without connecting to PostgreSQL")
    args = parser.parse_args()

    events = generate_events(args.count, args.seed)
    print(f"Prepared {len(events):,} synthetic events (seed={args.seed}).")
    if args.dry_run:
        print("Dry run: no database connection or inserts were made.")
        return

    try:
        import psycopg
        from dotenv import load_dotenv
    except ImportError as exc:
        raise SystemExit("Install the project dependencies first: pip install -r requirements.txt") from exc

    load_dotenv()
    required = ("DB_NAME", "DB_USER", "DB_PASSWORD")
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise SystemExit(
            "Missing database settings: " + ", ".join(missing)
            + ". Copy .env.example to .env and set your local credentials."
        )

    with psycopg.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        connect_timeout=5,
    ) as conn:
        with conn.cursor() as cur:
            cur.executemany(INSERT_SQL, events)

    print(f"Inserted {len(events):,} events into {os.environ['DB_NAME']}.")
    print("Scenarios include brute force, password spraying, a new device, impossible travel, and high login frequency.")


if __name__ == "__main__":
    main()
