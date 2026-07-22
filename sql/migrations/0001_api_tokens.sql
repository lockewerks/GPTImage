-- 0011_api_tokens.sql
--
-- Static bearer tokens for the HTTP transport. Each row is one credential: a
-- SHA-256 hex of the bearer string (the plaintext is shown once at mint time
-- and never stored), the principal it authenticates as, and the realm grants
-- it carries. Grants live in the row — not just in config — so a token can be
-- revoked or re-scoped without a config push or restart.
--
-- This is the phase-2 credential type (Claude Code, API-based agents). Phase 4
-- adds OAuth JWTs validated against Keycloak; both paths resolve to the same
-- RealmGrant the tools already understand.

CREATE TABLE IF NOT EXISTS gptimage.api_tokens (
    token_hash   TEXT PRIMARY KEY,          -- sha256 hex of the full bearer token
    principal    TEXT NOT NULL,
    grants       JSONB NOT NULL DEFAULT '{}'::jsonb,
        -- {"home":"nyx","read":["nyx","commons"],"write":["nyx","commons"],
        --  "max_sensitivity":"medium"}.  read/write may be ["*"] for all realms.
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    note         TEXT,                       -- human label, e.g. "claude-code laptop"
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS api_tokens_principal_idx
    ON gptimage.api_tokens (principal);
