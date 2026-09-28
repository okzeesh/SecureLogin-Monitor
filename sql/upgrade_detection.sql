-- Apply once to an existing SecureLogin Monitor database before running detections.
-- The unique index makes detection runs safe to repeat.

ALTER TABLE security_alerts
    ADD COLUMN IF NOT EXISTS dedupe_key VARCHAR(64);

CREATE UNIQUE INDEX IF NOT EXISTS security_alerts_dedupe_key_uidx
    ON security_alerts (dedupe_key);
