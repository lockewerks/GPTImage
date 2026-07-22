-- uninstall.sql
--
-- Drops the entire gptimage auth schema (tokens, OAuth clients/codes/refresh
-- tokens, credentials, migration history). Irreversible.
--
-- Run as a superuser against the gptimage database:
--   psql -U postgres -d gptimage -f sql/setup/uninstall.sql
--
-- To also drop the login role (optional):
--   psql -U postgres -c "DROP ROLE IF EXISTS gptimage_rw;"

DROP SCHEMA IF EXISTS gptimage CASCADE;
