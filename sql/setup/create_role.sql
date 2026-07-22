-- create_role.sql
--
-- Creates the gptimage_rw login role and the gptimage schema it owns. This is
-- the role gptimage_cli and gptimage_mcp connect as (database.user). The schema
-- holds ONLY the auth store: static bearer tokens and the OAuth server's
-- clients/codes/refresh tokens/credentials. No image data is ever stored.
--
-- GPTImage needs no Postgres extensions: token/code/secret hashing is done in
-- the application (SHA-256), and no pgvector/uuid-ossp is used.
--
-- Run ONCE as a superuser (typically postgres) against the gptimage database:
--   createdb -U postgres gptimage
--   psql -U postgres -d gptimage -v gptimage_pw='your_password' -f sql/setup/create_role.sql
--
-- Must run BEFORE `gptimage_cli migrate` so the migrate runner has a role to
-- connect as; migrate then creates the tables inside this schema.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gptimage_rw') THEN
        EXECUTE format('CREATE ROLE gptimage_rw LOGIN PASSWORD %L', :'gptimage_pw');
    END IF;
END
$$;

-- The migrate runner also creates the schema defensively; doing it here lets a
-- DBA set ownership/permissions before the first migrate.
CREATE SCHEMA IF NOT EXISTS gptimage AUTHORIZATION gptimage_rw;

GRANT USAGE ON SCHEMA gptimage TO gptimage_rw;
GRANT ALL ON ALL TABLES IN SCHEMA gptimage TO gptimage_rw;
GRANT ALL ON ALL SEQUENCES IN SCHEMA gptimage TO gptimage_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA gptimage
    GRANT ALL ON TABLES TO gptimage_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA gptimage
    GRANT ALL ON SEQUENCES TO gptimage_rw;
