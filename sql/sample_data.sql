-- SecureLogin Monitor — synthetic sample events for Step 3.
-- Run once after schema.sql. All identities, IPs, devices, and locations are fictional.
-- Timestamps use UTC+04:00 and are clustered to demonstrate detection patterns.

BEGIN;

INSERT INTO login_events (
    event_time, username, source_ip, country, device,
    login_method, status, failure_reason
)
VALUES
    -- Ordinary activity for Alice from her usual UAE laptop.
    ('2026-09-28 08:05:00+04', 'alice.rahman', '192.0.2.20', 'United Arab Emirates', 'Alice-Laptop', 'PASSWORD_MFA', 'SUCCESS', NULL),
    ('2026-09-28 08:32:00+04', 'alice.rahman', '192.0.2.20', 'United Arab Emirates', 'Alice-Laptop', 'SSO', 'SUCCESS', NULL),
    ('2026-09-28 11:17:00+04', 'alice.rahman', '192.0.2.20', 'United Arab Emirates', 'Alice-Laptop', 'PASSWORD_MFA', 'SUCCESS', NULL),

    -- Same user appears in the UK shortly after a UAE login: impossible-travel candidate.
    ('2026-09-28 12:02:00+04', 'alice.rahman', '198.51.100.44', 'United Kingdom', 'Alice-Unknown', 'PASSWORD_MFA', 'SUCCESS', NULL),

    -- New-device candidate for Bob; later detection can compare this with his known device.
    ('2026-09-28 09:10:00+04', 'bob.hassan', '192.0.2.57', 'United Arab Emirates', 'Bob-Desktop', 'PASSWORD_MFA', 'SUCCESS', NULL),
    ('2026-09-28 13:40:00+04', 'bob.hassan', '192.0.2.57', 'United Arab Emirates', 'Bob-Phone-New', 'PASSWORD_MFA', 'SUCCESS', NULL),

    -- Brute-force candidate: repeated failures against admin from one source IP.
    ('2026-09-28 14:15:01+04', 'admin', '203.0.113.77', 'Unknown', 'Unknown-Device', 'PASSWORD', 'FAILED', 'INVALID_PASSWORD'),
    ('2026-09-28 14:15:09+04', 'admin', '203.0.113.77', 'Unknown', 'Unknown-Device', 'PASSWORD', 'FAILED', 'INVALID_PASSWORD'),
    ('2026-09-28 14:15:16+04', 'admin', '203.0.113.77', 'Unknown', 'Unknown-Device', 'PASSWORD', 'FAILED', 'INVALID_PASSWORD'),
    ('2026-09-28 14:15:23+04', 'admin', '203.0.113.77', 'Unknown', 'Unknown-Device', 'PASSWORD', 'FAILED', 'INVALID_PASSWORD'),
    ('2026-09-28 14:15:31+04', 'admin', '203.0.113.77', 'Unknown', 'Unknown-Device', 'PASSWORD', 'FAILED', 'INVALID_PASSWORD'),
    ('2026-09-28 14:15:38+04', 'admin', '203.0.113.77', 'Unknown', 'Unknown-Device', 'PASSWORD', 'FAILED', 'INVALID_PASSWORD'),
    ('2026-09-28 14:15:46+04', 'admin', '203.0.113.77', 'Unknown', 'Unknown-Device', 'PASSWORD', 'FAILED', 'INVALID_PASSWORD'),
    ('2026-09-28 14:15:54+04', 'admin', '203.0.113.77', 'Unknown', 'Unknown-Device', 'PASSWORD', 'FAILED', 'INVALID_PASSWORD'),

    -- Similar bursts across several accounts from one IP: suspicious-IP candidate.
    ('2026-09-28 14:20:05+04', 'carol.khan', '203.0.113.88', 'Unknown', 'Unknown-Device', 'PASSWORD', 'FAILED', 'INVALID_USERNAME'),
    ('2026-09-28 14:20:12+04', 'david.ali', '203.0.113.88', 'Unknown', 'Unknown-Device', 'PASSWORD', 'FAILED', 'INVALID_PASSWORD'),
    ('2026-09-28 14:20:20+04', 'finance', '203.0.113.88', 'Unknown', 'Unknown-Device', 'PASSWORD', 'FAILED', 'INVALID_USERNAME'),

    -- Abnormal-frequency candidate: many successful events in a short window.
    ('2026-09-28 14:30:00+04', 'service.reports', '192.0.2.90', 'United Arab Emirates', 'Reports-Server', 'API_KEY', 'SUCCESS', NULL),
    ('2026-09-28 14:30:08+04', 'service.reports', '192.0.2.90', 'United Arab Emirates', 'Reports-Server', 'API_KEY', 'SUCCESS', NULL),
    ('2026-09-28 14:30:16+04', 'service.reports', '192.0.2.90', 'United Arab Emirates', 'Reports-Server', 'API_KEY', 'SUCCESS', NULL),
    ('2026-09-28 14:30:24+04', 'service.reports', '192.0.2.90', 'United Arab Emirates', 'Reports-Server', 'API_KEY', 'SUCCESS', NULL),
    ('2026-09-28 14:30:32+04', 'service.reports', '192.0.2.90', 'United Arab Emirates', 'Reports-Server', 'API_KEY', 'SUCCESS', NULL),

    -- A few unrelated failures and a later ordinary success for context.
    ('2026-09-28 14:42:00+04', 'eve.noor', '192.0.2.101', 'United Arab Emirates', 'Eve-Laptop', 'PASSWORD', 'FAILED', 'MFA_FAILED'),
    ('2026-09-28 14:43:00+04', 'eve.noor', '192.0.2.101', 'United Arab Emirates', 'Eve-Laptop', 'PASSWORD_MFA', 'SUCCESS', NULL),
    ('2026-09-28 14:47:00+04', 'frank.saeed', '192.0.2.112', 'United Arab Emirates', 'Frank-Laptop', 'SSO', 'FAILED', 'ACCOUNT_LOCKED');

COMMIT;
