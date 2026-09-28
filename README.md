# SecureLogin Monitor

Login monitoring pipeline:

Login Data → PostgreSQL → FastAPI → Security Detection → Dashboard

Version 1 stays small: two tables, no users/devices/IP directories yet.

## Step 1 — Data unit

**One row in `login_events` = one authentication attempt.**

The database stores raw events. Detection later writes rows to `security_alerts`. `risk_level` and `is_suspicious` are **not** stored on the event; those belong to alerts.

Schema file: `sql/schema.sql` (applied to the local `securelogin_db` database).

### `login_events`

| Column | Type | Required | Notes |
|---|---|---|---|
| `event_id` | `BIGSERIAL` | PK | Unique event id |
| `event_time` | `TIMESTAMPTZ` | yes | Timezone-aware (needed for impossible travel) |
| `username` | `VARCHAR(100)` | yes | Account that attempted login |
| `source_ip` | `INET` | yes | PostgreSQL IP type |
| `country` | `VARCHAR(100)` | no | GeoIP may be unknown |
| `device` | `VARCHAR(100)` | no | Device label; unknown devices allowed |
| `login_method` | `VARCHAR(30)` | yes | Enum below |
| `status` | `VARCHAR(20)` | yes | `SUCCESS` or `FAILED` |
| `failure_reason` | `VARCHAR(100)` | failed only | Null on success |

Allowed `login_method`: `PASSWORD`, `PASSWORD_MFA`, `SSO`, `CERTIFICATE`, `API_KEY`

Allowed `failure_reason`: `INVALID_PASSWORD`, `INVALID_USERNAME`, `MFA_FAILED`, `ACCOUNT_LOCKED`, `ACCOUNT_DISABLED`, `EXPIRED_CREDENTIALS`, `UNKNOWN`

Indexes support brute-force and frequency queries: time, username+time, IP+time, failed-only username+time.

### `security_alerts`

| Column | Type | Required | Notes |
|---|---|---|---|
| `alert_id` | `BIGSERIAL` | PK | Unique alert id |
| `alert_type` | `VARCHAR(40)` | yes | Detection rule that fired |
| `severity` | `VARCHAR(20)` | yes | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `source_ip` | `INET` | one of ip/user | May be null for user-only alerts |
| `username` | `VARCHAR(100)` | one of ip/user | May be null for IP-only alerts |
| `description` | `TEXT` | yes | Human-readable summary |
| `status` | `VARCHAR(20)` | yes | Default `OPEN` |
| `failed_attempt_count` | `INTEGER` | no | Useful for brute force |
| `window_start` / `window_end` | `TIMESTAMPTZ` | no | Detection window |
| `first_event_id` / `last_event_id` | `BIGINT` FK | no | Pointers into `login_events` |
| `created_at` / `updated_at` | `TIMESTAMPTZ` | yes | Alert lifecycle |

Allowed `alert_type`: `BRUTE_FORCE`, `SUSPICIOUS_IP`, `NEW_DEVICE`, `IMPOSSIBLE_TRAVEL`, `ABNORMAL_FREQUENCY`

Allowed alert `status`: `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE`

### Intentionally omitted (later versions)

- Separate `users`, `devices`, and `ip_addresses` tables
- Event-to-alert many-to-many evidence table
- Storing `risk_level` / `is_suspicious` on the raw event
- Auth, roles, realtime, Docker, ML

## Roadmap

1. Define schema — complete
2. Create PostgreSQL and apply `sql/schema.sql` — complete
3. Generate synthetic login events — 25 examples plus 5,000 generated events loaded
4. FastAPI read API — event, alert, and summary endpoints added
5. Detection rules — five V1 rules added
6. Dashboard — KPIs, charts, filters, events, and alerts added
7. Connect everything — verified against local PostgreSQL
8. Hardening (auth, Docker, ML)

## Step 3 — Synthetic sample events

`sql/sample_data.sql` contains 25 fictional login events. It includes ordinary activity, repeated failures for a brute-force pattern, one IP targeting multiple accounts, a new device, a rapid country change, and unusually frequent successful logins. The documentation-only IP ranges used by these records are reserved for examples; no real user data is included.

Apply the sample file once after the schema. It is intentionally a one-time seed script; running it again adds duplicate sample events.

For a larger dataset, configure `.env` as described below. Run `python scripts/generate_sample_events.py` to insert 5,000 reproducible events, or use `--count N`, `--seed N`, and `--dry-run` to customize or preview. The generator uses the V1 schema's constrained status, method, and failure-reason values. It does not store risk flags on raw events; detection rules derive alerts from event patterns. Re-running the generator adds more events.

## Step 4 — FastAPI read API

The API is in `api/main.py`. It serves the dashboard at `/` and exposes:

- `GET /health` — checks API and PostgreSQL connectivity
- `GET /login-events` — paginated event list with optional username, status, IP, and time filters
- `GET /security-alerts` — paginated alert list with optional username, status, and severity filters
- `GET /summary` — KPIs and chart aggregates for the dashboard

The list endpoints return up to 500 rows and include the full match count in `X-Total-Count`.

## Steps 5–7 — Detection, dashboard, and connection

The rules in `api/detection.py` look for:

- At least 5 failed attempts for one username and IP in a 5-minute bucket
- At least 8 failures from one IP across 5 or more accounts in a 10-minute bucket
- A successful login from a device not previously seen for that account
- Consecutive successful logins from known distant countries implying travel faster than 900 km/h within 12 hours
- At least 10 login events for an account in a 1-minute bucket

Country checks use approximate country-center coordinates; unknown locations are skipped. Detection runs are repeatable and suppress duplicate alerts with a stable `dedupe_key`.

For an existing database, apply the small additive migration once before running detection:

```powershell
& 'D:\postgresql\bin\psql.exe' -h localhost -U postgres -W -d securelogin_db -v ON_ERROR_STOP=1 -f 'sql\upgrade_detection.sql'
```

The dashboard is served by FastAPI at `/`. It includes 24-hour KPIs, hourly activity, open alerts, top failed source IPs, country counts, and a filterable/paginated login table.

### Local setup and run

1. Create a virtual environment if needed: `python -m venv .venv`.
2. Install dependencies: `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and enter the local PostgreSQL password in that file. Keep `.env` private; it is ignored by Git.
4. Load 5,000 events: `.\.venv\Scripts\python.exe scripts\generate_sample_events.py`.
5. Apply the detection migration with `.\.venv\Scripts\python.exe -m scripts.apply_detection_migration`, then run `.\.venv\Scripts\python.exe -m scripts.run_detection`.
6. Start the API and dashboard: `.\.venv\Scripts\python.exe -m uvicorn api.main:app --reload`.
7. Open `http://127.0.0.1:8000/`; API documentation is at `http://127.0.0.1:8000/docs`.

Step 7 verified: `/health` reports a database connection; the events endpoint returned 25 rows with 5,025 total; all five alert types appeared in the dashboard/API; the dashboard returned HTTP 200; and a second detection run created zero duplicate alerts. The current database contains the original 25 hand-authored examples, 5,000 generated events, and 15 open alerts (2 brute-force, 1 suspicious IP, 9 new-device, 2 impossible-travel, 1 abnormal-frequency).
