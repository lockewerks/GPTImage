#include "auth.hpp"

#include <gptimage/auth.hpp>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <string>

namespace gptimage {

using nlohmann::json;

namespace {

// The static gpt_ path: SHA-256 lookup in gptimage.api_tokens. Byte-for-byte
// the pre-OAuth behavior; Claude Code and scripted callers keep working.
AuthResult authenticate_static(const std::string& token, DbConn& db);

// The OAuth access-token path: RS256 verify (signature, iss, aud, exp all
// enforced inside JwtVerifier) -> principal via jwt_principal_claim +
// jwt_subject_map -> grant from [[auth.principals]]. Every step fails closed.
AuthResult authenticate_jwt(const std::string& token, const Config& cfg,
                            JwtVerifier* jwt) {
    AuthResult res;
    if (jwt == nullptr) {
        res.error = "JWT presented but JWT auth is not configured";
        return res;
    }

    std::string err;
    auto verified = jwt->verify(token, err);
    if (!verified) {
        res.error = "JWT verification failed: " + err;
        return res;
    }

    auto principal = resolve_jwt_principal(cfg.auth, verified->claims);
    if (!principal) {
        res.error = "JWT has no usable principal claim ('" +
                    cfg.auth.jwt_principal_claim + "')";
        return res;
    }

    auto grant = grant_from_config(cfg.auth, *principal);
    if (!grant) {
        // The kill switch: removing a principal from config revokes every
        // outstanding access token for it, without a token blocklist.
        res.error = "no [[auth.principals]] entry for '" + *principal + "'";
        return res;
    }

    res.ok    = true;
    res.grant = std::move(*grant);
    return res;
}

}  // namespace

AuthResult authenticate(const std::string& authorization_header,
                        DbConn& db,
                        const Config& cfg,
                        JwtVerifier* jwt) {
    AuthResult res;

    std::string token;
    if (!parse_bearer(authorization_header, token)) {
        res.error = "missing or malformed Authorization: Bearer header";
        return res;
    }

    // Dispatch on the token's shape. gpt_ is ours by construction; a compact
    // JWT is exactly three dot-separated segments. Anything else is neither
    // and gets a distinct log line (useful when a client pastes the wrong
    // kind of credential).
    if (token.rfind("gpt_", 0) == 0) {
        return authenticate_static(token, db);
    }
    const size_t dots = static_cast<size_t>(std::count(token.begin(), token.end(), '.'));
    if (dots == 2) {
        return authenticate_jwt(token, cfg, jwt);
    }
    res.error = "unrecognized token format (neither gpt_ bearer nor JWT)";
    return res;
}

namespace {

AuthResult authenticate_static(const std::string& token, DbConn& db) {
    AuthResult res;

    const std::string hash = sha256_hex(token);
    const std::string hash_prefix = hash.substr(0, 8);  // safe to log

    const char* sql =
        "SELECT token_hash, principal, grants::text, enabled "
        "FROM gptimage.api_tokens WHERE token_hash = $1";
    const char* params[] = { hash.c_str() };
    PGresult* r = PQexecParams(db.native(), sql, 1, nullptr, params, nullptr, nullptr, 0);
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        res.error = std::string("token lookup failed: ") + PQerrorMessage(db.native());
        PQclear(r);
        return res;
    }
    if (PQntuples(r) == 0) {
        res.error = "no token matching hash " + hash_prefix;
        PQclear(r);
        return res;
    }

    const std::string stored_hash = PQgetvalue(r, 0, 0);
    const std::string principal   = PQgetvalue(r, 0, 1);
    const std::string grants_str  = PQgetvalue(r, 0, 2);
    const bool enabled            = std::string(PQgetvalue(r, 0, 3)) == "t";
    PQclear(r);

    // Belt-and-braces: the PK WHERE already matched, but compare in constant
    // time so the check stays sound if the lookup key ever changes (e.g. to a
    // prefix scan).
    if (!constant_time_equals(stored_hash, hash)) {
        res.error = "token hash mismatch (" + hash_prefix + ")";
        return res;
    }
    if (!enabled) {
        res.error = "token disabled (" + hash_prefix + ", principal " + principal + ")";
        return res;
    }

    json grants = json::parse(grants_str, nullptr, /*allow_exceptions=*/false);
    if (grants.is_discarded()) {
        res.error = "token grants is not valid JSON (" + hash_prefix + ")";
        return res;
    }
    std::string err;
    RealmGrant grant;
    if (!grant_from_json(grants, principal, grant, err)) {
        res.error = "grant resolution failed (" + hash_prefix + "): " + err;
        return res;
    }

    // Best-effort touch of last_used_at; a failure here must not deny the call.
    const char* upd = "UPDATE gptimage.api_tokens SET last_used_at = now() WHERE token_hash = $1";
    PGresult* ur = PQexecParams(db.native(), upd, 1, nullptr, params, nullptr, nullptr, 0);
    if (PQresultStatus(ur) != PGRES_COMMAND_OK) {
        spdlog::warn("auth: last_used_at update failed for {}: {}", hash_prefix,
                     PQerrorMessage(db.native()));
    }
    PQclear(ur);

    res.ok    = true;
    res.grant = std::move(grant);
    return res;
}

}  // namespace

}  // namespace gptimage
