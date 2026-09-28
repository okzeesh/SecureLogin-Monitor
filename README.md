# SecureLogin Monitor

Login monitoring pipeline:

Login Data → PostgreSQL → FastAPI → Security Detection → Dashboard

Version 1 stays small: two tables, no users/devices/IP directories yet.

## Step 1 — Data unit (this milestone)

**One row in `login_events` = one authentication attempt.**

The database stores raw events. Detection later writes rows to `security_alerts`. `risk_level` and `is_suspicious` are **not** stored on the event; those belong to alerts.

Schema file: `sql/schema.sql` (not applied yet — Step 2).

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

1. Define schema — **current**
2. Create PostgreSQL and apply `sql/schema.sql`
3. Generate synthetic login events
4. FastAPI read API
5. Detection rules
6. Dashboard
7. End-to-end test
8. Hardening (auth, Docker, ML)
