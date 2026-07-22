-- 0003_audit_log.sql
--
-- Auth audit trail for the embedded OAuth server: logins, token issuance,
-- refresh rotations, and the security events (code reuse, brute-force) the AS
-- records. Writes are best-effort, so a missing table never blocks the auth
-- flow, but a real trail is worth having on a public-facing endpoint.
--
-- actor is the subsystem that wrote the row ('oauth'); principal is the
-- authenticated identity when one is known (NULL for pre-login events).

CREATE TABLE IF NOT EXISTS gptimage.audit_log (
    id         BIGSERIAL   PRIMARY KEY,
    actor      TEXT        NOT NULL,
    principal  TEXT,
    action     TEXT        NOT NULL,
    details    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_created_idx ON gptimage.audit_log (created_at);
CREATE INDEX IF NOT EXISTS audit_log_action_idx  ON gptimage.audit_log (action);
