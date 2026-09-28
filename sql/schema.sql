-- SecureLogin Monitor — Version 1 schema
-- One login_event = one authentication attempt.
-- Detection writes security_alerts; login_events stay raw.
-- Do not apply this until Step 2 (PostgreSQL setup).

CREATE TABLE login_events (
    event_id        BIGSERIAL PRIMARY KEY,
    event_time      TIMESTAMPTZ NOT NULL,
    username        VARCHAR(100) NOT NULL,
    source_ip       INET NOT NULL,
    country         VARCHAR(100),
    device          VARCHAR(100),
    login_method    VARCHAR(30) NOT NULL,
    status          VARCHAR(20) NOT NULL,
    failure_reason  VARCHAR(100),

    CONSTRAINT login_events_login_method_chk
        CHECK (login_method IN (
            'PASSWORD',
            'PASSWORD_MFA',
            'SSO',
            'CERTIFICATE',
            'API_KEY'
        )),

    CONSTRAINT login_events_status_chk
        CHECK (status IN ('SUCCESS', 'FAILED')),

    CONSTRAINT login_events_failure_reason_chk
        CHECK (failure_reason IS NULL OR failure_reason IN (
            'INVALID_PASSWORD',
            'INVALID_USERNAME',
            'MFA_FAILED',
            'ACCOUNT_LOCKED',
            'ACCOUNT_DISABLED',
            'EXPIRED_CREDENTIALS',
            'UNKNOWN'
        )),

    CONSTRAINT login_events_failure_consistency_chk
        CHECK (
            (status = 'SUCCESS' AND failure_reason IS NULL)
            OR
            (status = 'FAILED' AND failure_reason IS NOT NULL)
        )
);

CREATE INDEX login_events_event_time_idx
    ON login_events (event_time DESC);

CREATE INDEX login_events_username_time_idx
    ON login_events (username, event_time DESC);

CREATE INDEX login_events_source_ip_time_idx
    ON login_events (source_ip, event_time DESC);

CREATE INDEX login_events_failed_username_time_idx
    ON login_events (username, event_time DESC)
    WHERE status = 'FAILED';

CREATE TABLE security_alerts (
    alert_id            BIGSERIAL PRIMARY KEY,
    alert_type          VARCHAR(40) NOT NULL,
    severity            VARCHAR(20) NOT NULL,
    source_ip           INET,
    username            VARCHAR(100),
    description         TEXT NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    failed_attempt_count INTEGER,
    window_start        TIMESTAMPTZ,
    window_end          TIMESTAMPTZ,
    first_event_id      BIGINT REFERENCES login_events (event_id),
    last_event_id       BIGINT REFERENCES login_events (event_id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT security_alerts_type_chk
        CHECK (alert_type IN (
            'BRUTE_FORCE',
            'SUSPICIOUS_IP',
            'NEW_DEVICE',
            'IMPOSSIBLE_TRAVEL',
            'ABNORMAL_FREQUENCY'
        )),

    CONSTRAINT security_alerts_severity_chk
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    CONSTRAINT security_alerts_status_chk
        CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE')),

    CONSTRAINT security_alerts_subject_chk
        CHECK (source_ip IS NOT NULL OR username IS NOT NULL),

    CONSTRAINT security_alerts_window_chk
        CHECK (
            window_start IS NULL
            OR window_end IS NULL
            OR window_end >= window_start
        ),

    CONSTRAINT security_alerts_failed_count_chk
        CHECK (failed_attempt_count IS NULL OR failed_attempt_count >= 0)
);

CREATE INDEX security_alerts_open_idx
    ON security_alerts (severity, created_at DESC)
    WHERE status = 'OPEN';

CREATE INDEX security_alerts_username_idx
    ON security_alerts (username, created_at DESC);

CREATE INDEX security_alerts_source_ip_idx
    ON security_alerts (source_ip, created_at DESC);

CREATE INDEX security_alerts_type_status_idx
    ON security_alerts (alert_type, status);
