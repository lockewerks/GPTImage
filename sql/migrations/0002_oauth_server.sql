-- 0012_oauth_server.sql
--
-- Storage for the EMBEDDED OAuth 2.1 authorization server. This supersedes
-- the "phase 4 adds OAuth JWTs validated against Keycloak" plan noted in
-- 0011_api_tokens.sql — there is no Keycloak. GPTImage itself serves the
-- authorize/token/register endpoints and a built-in login page; claude.ai and
-- ChatGPT connectors register via RFC 7591 DCR and run the PKCE
-- authorization-code flow against it. Verified access tokens resolve to the
-- same RealmGrant the static api_tokens path produces.
--
-- Nothing secret is stored in plaintext: client secrets, authorization codes,
-- and refresh tokens all persist as SHA-256 hex of the credential, exactly
-- like api_tokens.token_hash. Access tokens are stateless RS256 JWTs and have
-- no table at all — the 1h TTL bounds exposure, and the kill switch is
-- removing the principal from [[auth.principals]] (auth fails closed on an
-- unknown principal).

-- Login credentials for the built-in authorize page. One row per principal
-- from [[auth.principals]]; written by `gptimage_cli passwd <principal>`.
-- password_phc is a PHC-format string ($scrypt$ln=..,r=..,p=..$salt$hash) so
-- the KDF and its parameters travel with the hash — a future argon2id swap
-- changes new rows only.
CREATE TABLE IF NOT EXISTS gptimage.principal_credentials (
    principal    TEXT PRIMARY KEY,
    password_phc TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Dynamically-registered OAuth clients (RFC 7591). claude.ai and ChatGPT
-- self-register at connector-add time; rows are cheap and prunable
-- (`gptimage_cli oauth clients prune`). redirect_uris are stored exactly as
-- registered and matched exactly at authorize time; registration already
-- enforced https + the redirect-host allowlist.
CREATE TABLE IF NOT EXISTS gptimage.oauth_clients (
    client_id           TEXT PRIMARY KEY,
    client_secret_hash  TEXT,               -- sha256 hex; NULL = public client (PKCE only)
    token_endpoint_auth TEXT NOT NULL DEFAULT 'none'
        CHECK (token_endpoint_auth IN ('none','client_secret_post','client_secret_basic')),
    client_name         TEXT,
    redirect_uris       JSONB NOT NULL,     -- array of exact-match https URIs
    scope               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ
);

-- Single-use authorization codes. Row lifetime is minutes: expires_at is
-- ~10 min out, used_at marks the one legitimate exchange, and the token
-- endpoint opportunistically deletes long-expired rows. A code presented
-- twice is a replay — the exchange revokes every refresh-token family the
-- code minted and refuses.
CREATE TABLE IF NOT EXISTS gptimage.oauth_codes (
    code_hash      TEXT PRIMARY KEY,        -- sha256 hex of the code; plaintext never stored
    client_id      TEXT NOT NULL REFERENCES gptimage.oauth_clients(client_id) ON DELETE CASCADE,
    principal      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,           -- must match the exchange's redirect_uri
    code_challenge TEXT NOT NULL,           -- PKCE S256 challenge (base64url of SHA-256)
    resource       TEXT,                    -- RFC 8707 binding when the client sent one
    scope          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ              -- set atomically by the single-use claim
);
CREATE INDEX IF NOT EXISTS oauth_codes_expires_idx
    ON gptimage.oauth_codes (expires_at);

-- Rotating refresh tokens. Every rotation inserts a successor sharing the
-- family_id and stamps rotated_at on the predecessor; presenting a token
-- whose rotated_at is already set is the classic theft signal (RFC 9700) and
-- revokes the whole family. expires_at slides forward on each rotation.
CREATE TABLE IF NOT EXISTS gptimage.oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,            -- sha256 hex; plaintext shown once to the client
    family_id  UUID NOT NULL,
    client_id  TEXT NOT NULL REFERENCES gptimage.oauth_clients(client_id) ON DELETE CASCADE,
    principal  TEXT NOT NULL,
    scope      TEXT,
    resource   TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ,                 -- successor issued; reuse after this = theft
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS oauth_refresh_family_idx
    ON gptimage.oauth_refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS oauth_refresh_principal_idx
    ON gptimage.oauth_refresh_tokens (principal);
