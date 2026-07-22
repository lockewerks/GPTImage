#pragma once

#include <gptimage/config.hpp>
#include <gptimage/db.hpp>
#include <gptimage/jwt_sign.hpp>

#include <nlohmann/json.hpp>

#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// Forward from libpq-fe.h (kept out of this header; oauth.cpp includes it).
struct pg_result;
typedef struct pg_result PGresult;

namespace httplib { class Server; }

// The embedded OAuth 2.1 authorization server: discovery metadata, dynamic
// client registration (RFC 7591), the PKCE authorization-code flow with a
// built-in login page, and rotating refresh tokens with reuse detection.
//
// Threading: OAuthService owns its own DbConn + mutex, deliberately separate
// from McpServer's exec_mtx_ — a login redirect or token refresh must never
// queue behind a multi-second embed+search on /mcp. OAuth QPS is ~zero, so a
// single serialized connection is plenty (db.hpp defers pooling on purpose).

namespace gptimage {

// One uniform failure shape for every endpoint. `http_status` is what the
// wire gets; `error` is the RFC 6749 error code; `description` is safe for
// the client (never token material, never DB internals).
//
// Status discipline that keeps fail2ban sane: bad login credentials are 401
// (that jail SHOULD count them); token-endpoint grant failures — expired
// codes, stale refresh tokens — are 400, NEVER 401, so claude.ai/ChatGPT
// backends retrying a dead token can't accumulate toward an IP ban.
struct OAuthError {
    int         http_status = 400;
    std::string error;        // "invalid_request", "invalid_grant", ...
    std::string description;
};

// Validated GET /oauth/authorize parameters, carried into the login form as
// hidden fields and re-validated on POST (hidden fields are untrusted input).
struct AuthorizeRequest {
    std::string client_id;
    std::string redirect_uri;
    std::string code_challenge;
    std::string state;
    std::string resource;
    std::string scope;
};

class OAuthService {
public:
    // `keys` is the shared signing-key set loaded by run_http(); front() is
    // the active key. The service holds the shared_ptr so key lifetime spans
    // both the verifier and the mint.
    OAuthService(const Config& cfg,
                 std::shared_ptr<const std::vector<SigningKey>> keys);

    // ----- discovery (pure memory, no DB, no lock) ---------------------------
    nlohmann::json metadata_protected_resource() const;
    nlohmann::json metadata_authorization_server() const;
    nlohmann::json jwks() const;

    // ----- RFC 7591 dynamic client registration ------------------------------
    // Returns the registration response (201 body) or an OAuthError. `ip` is
    // the rate-limit key (X-Forwarded-For first hop behind Caddy).
    std::variant<nlohmann::json, OAuthError>
    register_client(const nlohmann::json& request, const std::string& ip);

    // ----- authorize ---------------------------------------------------------
    // Validate GET /oauth/authorize query params. On failure: `redirect_error`
    // true means the error must be delivered via redirect (client identity was
    // verified); false means render a 400 page (never redirect to an
    // unverified URI — RFC 6749 §4.1.2.1).
    struct AuthorizeValidation {
        bool             ok = false;
        AuthorizeRequest req;
        OAuthError       error;
        bool             redirect_error = false;
    };
    AuthorizeValidation validate_authorize(
        const std::multimap<std::string, std::string>& params);

    // Handle the credentialed POST. On success returns the full redirect URL
    // (redirect_uri + code + state + iss). On failure returns an OAuthError:
    // 401 = bad credentials (re-render the form), 429 = throttled.
    std::variant<std::string, OAuthError>
    handle_login(const AuthorizeRequest& req,
                 const std::string& principal,
                 const std::string& password,
                 const std::string& ip);

    // ----- token endpoint ----------------------------------------------------
    // `authorization_header` carries client_secret_basic when used; form
    // params carry everything else. Returns the token response JSON or error.
    std::variant<nlohmann::json, OAuthError>
    token(const std::multimap<std::string, std::string>& form,
          const std::string& authorization_header);

    // Active signing key (mint side). Never null after construction.
    const SigningKey& active_key() const { return keys_->front(); }

private:
    struct ClientRow {
        std::string client_id;
        std::string secret_hash;   // empty = public client
        std::string auth_method;
        std::vector<std::string> redirect_uris;
    };

    // DB plumbing: lazy connect + one reset-and-retry on a dead connection
    // (same self-heal shape as Pipeline::ingest). Callers hold mtx_.
    DbConn& db();
    PGresult* exec(const char* sql, const std::vector<const char*>& params);

    std::optional<ClientRow> load_client(const std::string& client_id);

    // Resolve + authenticate the client on a token request. For 'none'
    // clients the form client_id identifies; secret clients must present
    // their secret via basic or post. Fails closed.
    std::variant<ClientRow, OAuthError>
    authenticate_client(const std::multimap<std::string, std::string>& form,
                        const std::string& authorization_header);

    std::variant<nlohmann::json, OAuthError>
    grant_authorization_code(const ClientRow& client,
                             const std::multimap<std::string, std::string>& form);
    std::variant<nlohmann::json, OAuthError>
    grant_refresh_token(const ClientRow& client,
                        const std::multimap<std::string, std::string>& form);

    // Mint the access-token JWT + a fresh refresh token row; shared by both
    // grants. `family` empty = start a new family.
    nlohmann::json issue_tokens(const std::string& principal,
                                const std::string& client_id,
                                const std::string& scope,
                                const std::string& resource,
                                std::string family);

    // Best-effort audit row, actor='oauth'. Never throws.
    void audit(const std::string& action, const std::string& principal,
               const nlohmann::json& details);

    // Sliding-window rate limiter. Records the event when under the limit;
    // self-bounds by pruning expired timestamps, erasing emptied keys, and a
    // hard cap on distinct keys so a flood of unique keys (spoofed IPs, random
    // principals) can't exhaust memory. Callers hold mtx_.
    bool over_limit(std::map<std::string, std::deque<int64_t>>& bucket,
                    const std::string& key, size_t max, int window_s);

    // Erase all-expired / empty keys from both rate maps. Throttled to run at
    // most once per minute (see last_sweep_), so steady-state cost is O(1) per
    // request and the maps track only keys active in the last window.
    void maybe_sweep_rate_maps(int64_t now);

    // Server-wide login gate checked BEFORE the scrypt KDF: caps aggregate
    // password-hash CPU regardless of which principal/IP a distributed
    // attacker uses. Returns true when the global window is saturated.
    bool global_login_saturated(int64_t now);

    const Config& cfg_;
    std::shared_ptr<const std::vector<SigningKey>> keys_;

    std::mutex              mtx_;
    std::unique_ptr<DbConn> db_;

    // key = principal (login fails) / ip (registration + login). Bounded — see
    // maybe_sweep_rate_maps + the hard cap in over_limit / handle_login.
    std::map<std::string, std::deque<int64_t>> login_fails_;
    std::map<std::string, std::deque<int64_t>> register_hits_;
    std::deque<int64_t>                         global_login_;  // server-wide scrypt gate
    int64_t                                     last_sweep_ = 0;
};

// Register every OAuth route (discovery, authorize, token, register, CORS
// preflights) on the transport's httplib server. Implemented in
// oauth_http.cpp; called by run_http() only when the signing key loaded.
void register_oauth_routes(httplib::Server& svr, OAuthService& oauth, const Config& cfg);

// ---------------------------------------------------------------------------
// Pure helpers, exposed for unit tests (implementation in oauth.cpp).
// ---------------------------------------------------------------------------

// RFC 7636 §4.1: 43–128 chars of [A-Za-z0-9-._~].
bool oauth_valid_pkce_string(const std::string& s);

// PKCE S256: base64url(SHA-256(verifier)), no padding.
std::string oauth_s256_challenge(const std::string& verifier);

// Host of an https:// URI, lowercased, port stripped; empty when not https,
// malformed, or carrying userinfo.
std::string oauth_https_host_of(const std::string& uri);

// Exact match or subdomain of an allowlist entry; empty allowlist = allow all.
bool oauth_host_allowed(const std::string& host, const std::vector<std::string>& allow);

// Cheap pre-parse guard: true if the raw JSON body nests no deeper than
// `max_depth`. nlohmann's recursive-descent parser can stack-overflow on
// pathologically nested input (bounded only by the 1 MiB body cap → a
// crash-restart DoS); this rejects it before parse. Brackets inside strings
// are ignored. Used on the public JSON endpoints (/mcp, /oauth/register).
bool json_within_depth(const std::string& body, int max_depth);

}  // namespace gptimage
