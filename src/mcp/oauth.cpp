#include "oauth.hpp"

#include <gptimage/auth.hpp>           // sha256_hex, constant_time_equals
#include <gptimage/password_hash.hpp>

#include <libpq-fe.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <stdexcept>

namespace gptimage {

using nlohmann::json;

namespace {

// base64url (RFC 4648 §5), no padding — local copy per house pattern.
std::string base64url(const unsigned char* data, size_t len) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        const uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(tbl[(n >> 6) & 63]);
        out.push_back(tbl[n & 63]);
    }
    if (len - i == 1) {
        const uint32_t n = uint32_t(data[i]) << 16;
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
    } else if (len - i == 2) {
        const uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(tbl[(n >> 6) & 63]);
    }
    return out;
}

// "<prefix>" + base64url(32 random bytes) — same construction as gpt_ tokens.
std::string random_token(const char* prefix) {
    std::array<unsigned char, 32> buf{};
    if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) {
        throw std::runtime_error("oauth: RAND_bytes failed");
    }
    return std::string(prefix) + base64url(buf.data(), buf.size());
}

// RFC 4122 v4 UUID from OpenSSL randomness (refresh-token family ids).
std::string new_uuid() {
    std::array<unsigned char, 16> b{};
    if (RAND_bytes(b.data(), static_cast<int>(b.size())) != 1) {
        throw std::runtime_error("oauth: RAND_bytes failed");
    }
    b[6] = static_cast<unsigned char>((b[6] & 0x0F) | 0x40);
    b[8] = static_cast<unsigned char>((b[8] & 0x3F) | 0x80);
    char out[37];
    std::snprintf(out, sizeof(out),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                  b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return std::string(out);
}


std::string url_encode(const std::string& s) {
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0x0F]);
        }
    }
    return out;
}

// Standard base64 decode (padded or not) for HTTP Basic credentials.
bool b64_std_decode(const std::string& in, std::string& out) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.clear();
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=') break;
        const int v = val(c);
        if (v < 0) return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    return true;
}

std::string param(const std::multimap<std::string, std::string>& m, const char* key) {
    const auto it = m.find(key);
    return it == m.end() ? std::string() : it->second;
}

int64_t now_s() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}

OAuthError err(int status, const char* code, std::string desc) {
    return OAuthError{status, code, std::move(desc)};
}

}  // namespace

// ---------------------------------------------------------------------------
// Pure helpers (declared in oauth.hpp; unit-tested in test_oauth.cpp)
// ---------------------------------------------------------------------------

// RFC 7636 §4.1 charset: [A-Za-z0-9-._~], length 43–128.
bool oauth_valid_pkce_string(const std::string& s) {
    if (s.size() < 43 || s.size() > 128) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~';
    });
}

std::string oauth_s256_challenge(const std::string& verifier) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(verifier.data()), verifier.size(), digest);
    return base64url(digest, sizeof(digest));
}

// Deliberately tiny — accepts only what registration should. Rejects
// userinfo outright (nothing legitimate registers with one, and it enables
// lookalike URIs).
std::string oauth_https_host_of(const std::string& uri) {
    constexpr const char* kScheme = "https://";
    if (uri.rfind(kScheme, 0) != 0) return {};
    const size_t host_start = std::string(kScheme).size();
    size_t host_end = uri.find_first_of("/?#", host_start);
    if (host_end == std::string::npos) host_end = uri.size();
    std::string host = uri.substr(host_start, host_end - host_start);
    if (host.find('@') != std::string::npos) return {};
    if (const size_t colon = host.find(':'); colon != std::string::npos) {
        host.resize(colon);
    }
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return host;
}

bool json_within_depth(const std::string& body, int max_depth) {
    int depth = 0;
    bool in_str = false, escaped = false;
    for (char c : body) {
        if (in_str) {
            if (escaped)      escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"')  in_str = false;
            continue;
        }
        if (c == '"') in_str = true;
        else if (c == '{' || c == '[') { if (++depth > max_depth) return false; }
        else if (c == '}' || c == ']') { if (depth > 0) --depth; }
    }
    return true;
}

// "claude.ai" allows "claude.ai" and "api.claude.ai", never "notclaude.ai".
bool oauth_host_allowed(const std::string& host, const std::vector<std::string>& allow) {
    if (allow.empty()) return true;  // explicit "allow everything" config
    if (host.empty()) return false;
    for (const auto& entry : allow) {
        if (host == entry) return true;
        if (host.size() > entry.size() + 1 &&
            host.compare(host.size() - entry.size() - 1, entry.size() + 1, "." + entry) == 0) {
            return true;
        }
    }
    return false;
}

OAuthService::OAuthService(const Config& cfg,
                           std::shared_ptr<const std::vector<SigningKey>> keys)
    : cfg_(cfg), keys_(std::move(keys)) {
    if (!keys_ || keys_->empty()) {
        throw std::runtime_error("oauth: OAuthService requires at least one signing key");
    }
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

json OAuthService::metadata_protected_resource() const {
    return json{
        {"resource", cfg_.auth.oauth.resource},
        {"authorization_servers", json::array({cfg_.auth.oauth.issuer})},
        {"bearer_methods_supported", json::array({"header"})},
        {"scopes_supported", json::array({"mcp"})},
    };
}

json OAuthService::metadata_authorization_server() const {
    const std::string& iss = cfg_.auth.oauth.issuer;
    return json{
        {"issuer", iss},
        {"authorization_endpoint", iss + "/oauth/authorize"},
        {"token_endpoint", iss + "/oauth/token"},
        {"registration_endpoint", iss + "/oauth/register"},
        {"jwks_uri", iss + "/.well-known/jwks.json"},
        {"response_types_supported", json::array({"code"})},
        {"grant_types_supported", json::array({"authorization_code", "refresh_token"})},
        {"code_challenge_methods_supported", json::array({"S256"})},
        {"token_endpoint_auth_methods_supported",
         json::array({"none", "client_secret_post", "client_secret_basic"})},
        {"scopes_supported", json::array({"mcp"})},
    };
}

json OAuthService::jwks() const { return jwks_json(*keys_); }

// ---------------------------------------------------------------------------
// DB plumbing
// ---------------------------------------------------------------------------

DbConn& OAuthService::db() {
    if (!db_) db_ = std::make_unique<DbConn>(cfg_.database);
    return *db_;
}

PGresult* OAuthService::exec(const char* sql, const std::vector<const char*>& params) {
    PGresult* r = PQexecParams(db().native(), sql, static_cast<int>(params.size()),
                               nullptr, params.data(), nullptr, nullptr, 0);
    const auto st = PQresultStatus(r);
    if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
        // Self-heal a dead connection once (network flap, VPS PG restart) —
        // the same shape Pipeline::ingest uses at its choke point.
        if (!db().alive()) {
            spdlog::warn("oauth: db connection dead, resetting ({})", db().label());
            PQclear(r);
            db().reset();
            r = PQexecParams(db().native(), sql, static_cast<int>(params.size()),
                             nullptr, params.data(), nullptr, nullptr, 0);
        }
    }
    return r;
}

// ---------------------------------------------------------------------------
// Audit + rate limiting
// ---------------------------------------------------------------------------

void OAuthService::audit(const std::string& action, const std::string& principal,
                         const json& details) {
    try {
        const std::string details_str = details.dump();
        const char* sql =
            "INSERT INTO gptimage.audit_log (actor, principal, action, details) "
            "VALUES ('oauth', NULLIF($1,''), $2, $3::jsonb)";
        PGresult* r = exec(sql, {principal.c_str(), action.c_str(), details_str.c_str()});
        if (PQresultStatus(r) != PGRES_COMMAND_OK) {
            spdlog::warn("oauth: audit insert failed: {}", PQerrorMessage(db().native()));
        }
        PQclear(r);
    } catch (const std::exception& e) {
        spdlog::warn("oauth: audit failed: {}", e.what());
    }
}

namespace {
// Hard ceiling on distinct keys per rate map (spoofed-IP / random-principal
// flood backstop). Well above any legitimate active-client count.
constexpr size_t kMaxRateKeys = 16384;
// Server-wide login gate: at most this many login attempts (each a potential
// scrypt) per window, across all principals and IPs.
constexpr int    kGlobalLoginMax    = 30;
constexpr int    kGlobalLoginWindow = 10;  // seconds
}  // namespace

void OAuthService::maybe_sweep_rate_maps(int64_t now) {
    if (now - last_sweep_ < 60) return;  // amortize: at most once/minute
    last_sweep_ = now;
    // login_fails_ entries expire after 15 min, register_hits_ after 1 h; a
    // conservative single horizon (1 h) drops anything definitely idle without
    // needing per-bucket windows here.
    for (auto* bucket : {&login_fails_, &register_hits_}) {
        for (auto it = bucket->begin(); it != bucket->end(); ) {
            auto& q = it->second;
            while (!q.empty() && q.front() < now - 3600) q.pop_front();
            if (q.empty()) it = bucket->erase(it);
            else ++it;
        }
    }
}

bool OAuthService::global_login_saturated(int64_t now) {
    while (!global_login_.empty() && global_login_.front() < now - kGlobalLoginWindow) {
        global_login_.pop_front();
    }
    if (global_login_.size() >= static_cast<size_t>(kGlobalLoginMax)) return true;
    global_login_.push_back(now);
    return false;
}

bool OAuthService::over_limit(std::map<std::string, std::deque<int64_t>>& bucket,
                              const std::string& key, size_t max, int window_s) {
    const int64_t now = now_s();
    maybe_sweep_rate_maps(now);

    auto it = bucket.find(key);
    if (it != bucket.end()) {
        auto& q = it->second;
        while (!q.empty() && q.front() < now - window_s) q.pop_front();
        if (q.empty()) { bucket.erase(it); it = bucket.end(); }
        else if (q.size() >= max) return true;
    }
    // Adding a brand-new key while at the cap: force a sweep, and if the map is
    // still saturated, shed (treat as limited) rather than grow without bound.
    if (it == bucket.end() && bucket.size() >= kMaxRateKeys) {
        last_sweep_ = 0;
        maybe_sweep_rate_maps(now);
        if (bucket.size() >= kMaxRateKeys) return true;
    }
    bucket[key].push_back(now);
    return false;
}

// ---------------------------------------------------------------------------
// RFC 7591 dynamic client registration
// ---------------------------------------------------------------------------

std::variant<json, OAuthError>
OAuthService::register_client(const json& request, const std::string& ip) {
    std::lock_guard<std::mutex> lk(mtx_);

    // Cheap validation FIRST — a malformed body is rejected without touching
    // the rate map or the database, so junk can't grow state or queue DB work.
    if (!request.is_object()) {
        return err(400, "invalid_client_metadata", "request body must be a JSON object");
    }

    // redirect_uris: required, https-only, host allowlisted, no fragment.
    const auto uris_it = request.find("redirect_uris");
    if (uris_it == request.end() || !uris_it->is_array() || uris_it->empty()) {
        return err(400, "invalid_redirect_uri", "redirect_uris (non-empty array) is required");
    }
    std::vector<std::string> redirect_uris;
    for (const auto& u : *uris_it) {
        if (!u.is_string()) {
            return err(400, "invalid_redirect_uri", "redirect_uris entries must be strings");
        }
        const std::string uri = u.get<std::string>();
        // A fragment would survive to authorize, where ?code=... is appended
        // AFTER the '#' → a broken/again-fragmented callback. Reject outright.
        if (uri.find('#') != std::string::npos) {
            return err(400, "invalid_redirect_uri",
                       "redirect_uris must not contain a fragment: " + uri);
        }
        const std::string host = oauth_https_host_of(uri);
        if (host.empty()) {
            return err(400, "invalid_redirect_uri",
                       "redirect_uris must be https:// URIs: " + uri);
        }
        if (!oauth_host_allowed(host, cfg_.auth.oauth.redirect_hosts)) {
            return err(400, "invalid_redirect_uri",
                       "redirect host '" + host + "' is not on this server's allowlist");
        }
        redirect_uris.push_back(uri);
    }

    // token_endpoint_auth_method: RFC 7591 defaults to client_secret_basic.
    std::string auth_method = request.value("token_endpoint_auth_method",
                                            std::string("client_secret_basic"));
    if (auth_method != "none" && auth_method != "client_secret_post" &&
        auth_method != "client_secret_basic") {
        return err(400, "invalid_client_metadata",
                   "unsupported token_endpoint_auth_method '" + auth_method + "'");
    }

    // Rate-limit AFTER cheap validation but BEFORE the DB count / insert, so a
    // flood of well-formed registrations is shed before it queues DB work under
    // the mutex. Keyed on the trustworthy client IP (see oauth_http client_ip).
    if (over_limit(register_hits_, ip, 5, 3600)) {
        return err(429, "invalid_client_metadata", "registration rate limit exceeded");
    }

    // Client-count cap: a personal server registering its 51st client is
    // either under attack or badly misconfigured; refuse loudly either way.
    {
        PGresult* r = exec("SELECT count(*) FROM gptimage.oauth_clients", {});
        const bool ok = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;
        const long count = ok ? std::strtol(PQgetvalue(r, 0, 0), nullptr, 10) : 0;
        PQclear(r);
        if (!ok) return err(500, "server_error", "client count query failed");
        if (count >= cfg_.auth.oauth.max_clients) {
            spdlog::warn("oauth: registration refused — max_clients ({}) reached",
                         cfg_.auth.oauth.max_clients);
            return err(403, "invalid_client_metadata",
                       "client registry is full; prune with gptimage_cli oauth clients prune");
        }
    }

    const std::string client_id   = random_token("gpt_c_").substr(0, 6 + 22);
    const std::string client_name = request.value("client_name", std::string());
    const std::string scope       = request.value("scope", std::string("mcp"));

    std::string secret, secret_hash;
    if (auth_method != "none") {
        secret      = random_token("gpt_s_");
        secret_hash = sha256_hex(secret);
    }

    const json uris_json = redirect_uris;
    const std::string uris_str = uris_json.dump();
    const char* sql =
        "INSERT INTO gptimage.oauth_clients "
        "(client_id, client_secret_hash, token_endpoint_auth, client_name, redirect_uris, scope) "
        "VALUES ($1, NULLIF($2,''), $3, NULLIF($4,''), $5::jsonb, $6)";
    PGresult* r = exec(sql, {client_id.c_str(), secret_hash.c_str(), auth_method.c_str(),
                             client_name.c_str(), uris_str.c_str(), scope.c_str()});
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        const std::string db_err = PQerrorMessage(db().native());
        PQclear(r);
        spdlog::error("oauth: client insert failed: {}", db_err);
        return err(500, "server_error", "registration storage failed");
    }
    PQclear(r);

    audit("client_registered", "",
          {{"client_id", client_id}, {"client_name", client_name},
           {"auth_method", auth_method}, {"redirect_uris", uris_json}, {"ip", ip}});
    spdlog::info("oauth: registered client {} ({}) auth={} uris={}",
                 client_id, client_name.empty() ? "<unnamed>" : client_name,
                 auth_method, uris_str);

    json resp{
        {"client_id", client_id},
        {"client_id_issued_at", now_s()},
        {"redirect_uris", uris_json},
        {"token_endpoint_auth_method", auth_method},
        {"grant_types", json::array({"authorization_code", "refresh_token"})},
        {"response_types", json::array({"code"})},
        {"scope", scope},
    };
    if (!client_name.empty()) resp["client_name"] = client_name;
    if (!secret.empty()) {
        resp["client_secret"] = secret;  // shown once; only the hash is stored
        resp["client_secret_expires_at"] = 0;
    }
    return resp;
}

// ---------------------------------------------------------------------------
// Authorize
// ---------------------------------------------------------------------------

std::optional<OAuthService::ClientRow>
OAuthService::load_client(const std::string& client_id) {
    const char* sql =
        "SELECT client_id, coalesce(client_secret_hash,''), token_endpoint_auth, "
        "       redirect_uris::text "
        "FROM gptimage.oauth_clients WHERE client_id = $1";
    PGresult* r = exec(sql, {client_id.c_str()});
    if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) != 1) {
        PQclear(r);
        return std::nullopt;
    }
    ClientRow row;
    row.client_id   = PQgetvalue(r, 0, 0);
    row.secret_hash = PQgetvalue(r, 0, 1);
    row.auth_method = PQgetvalue(r, 0, 2);
    const json uris = json::parse(PQgetvalue(r, 0, 3), nullptr, /*allow_exceptions=*/false);
    PQclear(r);
    if (uris.is_array()) {
        for (const auto& u : uris) {
            if (u.is_string()) row.redirect_uris.push_back(u.get<std::string>());
        }
    }
    return row;
}

OAuthService::AuthorizeValidation
OAuthService::validate_authorize(const std::multimap<std::string, std::string>& params) {
    std::lock_guard<std::mutex> lk(mtx_);
    AuthorizeValidation v;
    v.req.client_id      = param(params, "client_id");
    v.req.redirect_uri   = param(params, "redirect_uri");
    v.req.code_challenge = param(params, "code_challenge");
    v.req.state          = param(params, "state");
    v.req.resource       = param(params, "resource");
    v.req.scope          = param(params, "scope");

    // Client identity first — nothing may redirect until the redirect_uri is
    // proven to belong to a registered client (RFC 6749 §4.1.2.1).
    if (v.req.client_id.empty()) {
        v.error = err(400, "invalid_request", "client_id is required");
        return v;
    }
    auto client = load_client(v.req.client_id);
    if (!client) {
        v.error = err(400, "invalid_request", "unknown client_id");
        return v;
    }
    if (v.req.redirect_uri.empty() ||
        std::find(client->redirect_uris.begin(), client->redirect_uris.end(),
                  v.req.redirect_uri) == client->redirect_uris.end()) {
        v.error = err(400, "invalid_request",
                      "redirect_uri does not match any registered URI for this client");
        return v;
    }

    // From here the client is real — errors go back via redirect.
    v.redirect_error = true;

    if (param(params, "response_type") != "code") {
        v.error = err(400, "unsupported_response_type", "only response_type=code is supported");
        return v;
    }
    const std::string method = param(params, "code_challenge_method");
    if (v.req.code_challenge.empty()) {
        v.error = err(400, "invalid_request", "PKCE is required: code_challenge missing");
        return v;
    }
    if (method != "S256") {
        v.error = err(400, "invalid_request", "code_challenge_method must be S256");
        return v;
    }
    if (!oauth_valid_pkce_string(v.req.code_challenge)) {
        v.error = err(400, "invalid_request", "code_challenge must be 43-128 unreserved chars");
        return v;
    }
    if (!v.req.resource.empty() && v.req.resource != cfg_.auth.oauth.resource) {
        v.error = err(400, "invalid_target",
                      "resource must be " + cfg_.auth.oauth.resource);
        return v;
    }
    if (v.req.state.size() > 2048) {
        v.error = err(400, "invalid_request", "state too large");
        return v;
    }

    v.ok = true;
    return v;
}

std::variant<std::string, OAuthError>
OAuthService::handle_login(const AuthorizeRequest& req,
                           const std::string& principal,
                           const std::string& password,
                           const std::string& ip) {
    std::lock_guard<std::mutex> lk(mtx_);

    // Throttle BEFORE the expensive KDF, in three layers:
    //   1. server-wide gate — caps aggregate scrypt CPU regardless of which
    //      principal/IP a distributed attacker rotates through;
    //   2. per-principal — 5 failed tries / 15 min (the IP-independent cap that
    //      actually contains password guessing; note it is also an account-
    //      lockout lever, bounded to a 15-min window and rare-login model);
    //   3. per-IP — a wider spray net (now keyed on the trustworthy client IP).
    // fail2ban is the outer wall on the real peer. The check path prunes and
    // erases empty keys so it never grows the map.
    {
        const int64_t now = now_s();
        maybe_sweep_rate_maps(now);
        if (global_login_saturated(now)) {
            return err(429, "slow_down", "server busy; try again shortly");
        }
        auto count_recent = [&](const std::string& key) -> size_t {
            auto it = login_fails_.find(key);
            if (it == login_fails_.end()) return 0;
            auto& q = it->second;
            while (!q.empty() && q.front() < now - 900) q.pop_front();
            if (q.empty()) { login_fails_.erase(it); return 0; }
            return q.size();
        };
        if (count_recent("p:" + principal) >= 5 || count_recent("ip:" + ip) >= 20) {
            return err(429, "slow_down", "too many failed logins; try again later");
        }
    }

    if (principal.empty() || password.empty()) {
        return err(401, "access_denied", "principal and password are required");
    }

    // Fetch the stored PHC. A missing row still burns one scrypt derivation
    // against a dummy hash so "unknown principal" and "wrong password" are
    // indistinguishable by timing.
    std::string stored_phc;
    {
        const char* sql =
            "SELECT password_phc FROM gptimage.principal_credentials WHERE principal = $1";
        PGresult* r = exec(sql, {principal.c_str()});
        if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) {
            stored_phc = PQgetvalue(r, 0, 0);
        }
        PQclear(r);
    }
    bool ok;
    if (stored_phc.empty()) {
        static const std::string kDummy = hash_password("gptimage-dummy-timing-pad");
        (void)verify_password(password, kDummy);
        ok = false;
    } else {
        ok = verify_password(password, stored_phc);
    }

    if (!ok) {
        const int64_t now = now_s();
        // Bound the failure map before recording (distinct-principal/IP flood).
        if (login_fails_.size() >= kMaxRateKeys) { last_sweep_ = 0; maybe_sweep_rate_maps(now); }
        if (login_fails_.size() < kMaxRateKeys) {
            login_fails_["p:" + principal].push_back(now);
            login_fails_["ip:" + ip].push_back(now);
        }
        audit("login_failed", principal, {{"client_id", req.client_id}, {"ip", ip}});
        spdlog::warn("oauth: failed login for '{}' from {}", principal, ip);
        return err(401, "access_denied", "invalid principal or password");
    }

    login_fails_.erase("p:" + principal);

    // Principal must also resolve a grant — a password without a
    // [[auth.principals]] entry authenticates nothing.
    if (!grant_from_config(cfg_.auth, principal)) {
        audit("login_failed", principal,
              {{"client_id", req.client_id}, {"reason", "no_principal_config"}});
        return err(401, "access_denied", "principal has no configured grant");
    }

    // Mint the single-use code, bound to everything the exchange must match.
    const std::string code = random_token("rlqa_");
    const std::string code_hash = sha256_hex(code);
    const std::string ttl = std::to_string(cfg_.auth.oauth.auth_code_ttl_s);
    const char* sql =
        "INSERT INTO gptimage.oauth_codes "
        "(code_hash, client_id, principal, redirect_uri, code_challenge, resource, scope, expires_at) "
        "VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), NULLIF($7,''), now() + make_interval(secs => $8::int))";
    PGresult* r = exec(sql, {code_hash.c_str(), req.client_id.c_str(), principal.c_str(),
                             req.redirect_uri.c_str(), req.code_challenge.c_str(),
                             req.resource.c_str(), req.scope.c_str(), ttl.c_str()});
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        const std::string db_err = PQerrorMessage(db().native());
        PQclear(r);
        spdlog::error("oauth: code insert failed: {}", db_err);
        return err(500, "server_error", "could not issue authorization code");
    }
    PQclear(r);

    audit("login", principal, {{"client_id", req.client_id}, {"ip", ip}});
    spdlog::info("oauth: '{}' authorized client {} from {}", principal, req.client_id, ip);

    std::string redirect = req.redirect_uri;
    redirect += (redirect.find('?') == std::string::npos) ? '?' : '&';
    redirect += "code=" + url_encode(code);
    if (!req.state.empty()) redirect += "&state=" + url_encode(req.state);
    redirect += "&iss=" + url_encode(cfg_.auth.oauth.issuer);  // RFC 9207
    return redirect;
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

std::variant<OAuthService::ClientRow, OAuthError>
OAuthService::authenticate_client(const std::multimap<std::string, std::string>& form,
                                  const std::string& authorization_header) {
    std::string client_id     = param(form, "client_id");
    std::string client_secret = param(form, "client_secret");
    bool basic = false;

    // client_secret_basic: Authorization: Basic base64(id:secret). Values are
    // form-urlencoded per RFC 6749 §2.3.1 — but our ids/secrets are base64url
    // strings with no reserved characters, so a plain split is exact.
    if (!authorization_header.empty()) {
        const std::string kBasic = "Basic ";
        if (authorization_header.rfind(kBasic, 0) == 0) {
            std::string decoded;
            if (!b64_std_decode(authorization_header.substr(kBasic.size()), decoded)) {
                return err(401, "invalid_client", "malformed Basic credentials");
            }
            const size_t colon = decoded.find(':');
            if (colon == std::string::npos) {
                return err(401, "invalid_client", "malformed Basic credentials");
            }
            client_id     = decoded.substr(0, colon);
            client_secret = decoded.substr(colon + 1);
            basic = true;
        }
    }

    if (client_id.empty()) {
        return err(401, "invalid_client", "client_id is required");
    }
    auto client = load_client(client_id);
    if (!client) {
        return err(401, "invalid_client", "unknown client");
    }

    if (client->auth_method == "none") {
        // Public client: identified, not authenticated. PKCE is the proof.
        return *client;
    }
    if (client->auth_method == "client_secret_basic" && !basic) {
        return err(401, "invalid_client", "client must authenticate with Basic");
    }
    if (client_secret.empty() ||
        !constant_time_equals(sha256_hex(client_secret), client->secret_hash)) {
        return err(401, "invalid_client", "client authentication failed");
    }
    return *client;
}

std::variant<json, OAuthError>
OAuthService::token(const std::multimap<std::string, std::string>& form,
                    const std::string& authorization_header) {
    std::lock_guard<std::mutex> lk(mtx_);

    auto client_or = authenticate_client(form, authorization_header);
    if (std::holds_alternative<OAuthError>(client_or)) {
        return std::get<OAuthError>(client_or);
    }
    const ClientRow& client = std::get<ClientRow>(client_or);

    // Touch last_used_at, best effort.
    {
        PGresult* r = exec(
            "UPDATE gptimage.oauth_clients SET last_used_at = now() WHERE client_id = $1",
            {client.client_id.c_str()});
        PQclear(r);
    }

    const std::string grant_type = param(form, "grant_type");
    if (grant_type == "authorization_code") return grant_authorization_code(client, form);
    if (grant_type == "refresh_token")      return grant_refresh_token(client, form);
    return err(400, "unsupported_grant_type",
               "grant_type must be authorization_code or refresh_token");
}

std::variant<json, OAuthError>
OAuthService::grant_authorization_code(const ClientRow& client,
                                       const std::multimap<std::string, std::string>& form) {
    const std::string code         = param(form, "code");
    const std::string verifier     = param(form, "code_verifier");
    const std::string redirect_uri = param(form, "redirect_uri");
    if (code.empty())     return err(400, "invalid_request", "code is required");
    if (verifier.empty()) return err(400, "invalid_request", "code_verifier is required");

    const std::string code_hash = sha256_hex(code);

    // Atomic single-use claim: exactly one exchange can flip used_at.
    const char* claim_sql =
        "UPDATE gptimage.oauth_codes SET used_at = now() "
        "WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now() "
        "RETURNING client_id, principal, redirect_uri, code_challenge, "
        "          coalesce(resource,''), coalesce(scope,'')";
    PGresult* r = exec(claim_sql, {code_hash.c_str()});
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        PQclear(r);
        return err(500, "server_error", "code claim failed");
    }
    if (PQntuples(r) == 0) {
        PQclear(r);
        // Replay or expiry? A used code is the attack signal: kill every
        // refresh token this principal+client pair holds. (At two principals
        // and a handful of clients, principal+client scope is the family the
        // code created, minus bookkeeping.)
        PGresult* probe = exec(
            "SELECT principal, used_at IS NOT NULL FROM gptimage.oauth_codes WHERE code_hash = $1",
            {code_hash.c_str()});
        if (PQresultStatus(probe) == PGRES_TUPLES_OK && PQntuples(probe) == 1 &&
            std::string(PQgetvalue(probe, 0, 1)) == "t") {
            const std::string principal = PQgetvalue(probe, 0, 0);
            PQclear(probe);
            PGresult* rev = exec(
                "UPDATE gptimage.oauth_refresh_tokens SET revoked_at = now() "
                "WHERE principal = $1 AND client_id = $2 AND revoked_at IS NULL",
                {principal.c_str(), client.client_id.c_str()});
            PQclear(rev);
            audit("code_replay_detected", principal, {{"client_id", client.client_id}});
            spdlog::warn("oauth: authorization code REPLAY for '{}' client {} — refresh tokens revoked",
                         principal, client.client_id);
        } else {
            PQclear(probe);
        }
        return err(400, "invalid_grant", "authorization code is invalid, expired, or already used");
    }

    const std::string bound_client   = PQgetvalue(r, 0, 0);
    const std::string principal      = PQgetvalue(r, 0, 1);
    const std::string bound_redirect = PQgetvalue(r, 0, 2);
    const std::string challenge      = PQgetvalue(r, 0, 3);
    const std::string resource       = PQgetvalue(r, 0, 4);
    const std::string scope          = PQgetvalue(r, 0, 5);
    PQclear(r);

    if (bound_client != client.client_id) {
        return err(400, "invalid_grant", "code was issued to a different client");
    }
    if (!redirect_uri.empty() && redirect_uri != bound_redirect) {
        return err(400, "invalid_grant", "redirect_uri does not match the authorization request");
    }
    if (!oauth_valid_pkce_string(verifier) ||
        !constant_time_equals(oauth_s256_challenge(verifier), challenge)) {
        return err(400, "invalid_grant", "PKCE verification failed");
    }
    if (const std::string req_resource = param(form, "resource");
        !req_resource.empty() && !resource.empty() && req_resource != resource) {
        return err(400, "invalid_target", "resource does not match the authorization request");
    }

    // Housekeeping: codes older than a day are noise by definition.
    {
        PGresult* gc = exec(
            "DELETE FROM gptimage.oauth_codes WHERE expires_at < now() - interval '1 day'", {});
        PQclear(gc);
    }

    return issue_tokens(principal, client.client_id, scope, resource, /*family=*/"");
}

std::variant<json, OAuthError>
OAuthService::grant_refresh_token(const ClientRow& client,
                                  const std::multimap<std::string, std::string>& form) {
    const std::string token = param(form, "refresh_token");
    if (token.empty()) return err(400, "invalid_request", "refresh_token is required");

    const std::string token_hash = sha256_hex(token);
    const char* sql =
        "SELECT family_id::text, client_id, principal, coalesce(scope,''), coalesce(resource,''), "
        "       (expires_at <= now()) AS expired, "
        "       (rotated_at IS NOT NULL) AS rotated, "
        "       (revoked_at IS NOT NULL) AS revoked "
        "FROM gptimage.oauth_refresh_tokens WHERE token_hash = $1";
    PGresult* r = exec(sql, {token_hash.c_str()});
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        PQclear(r);
        return err(500, "server_error", "refresh lookup failed");
    }
    if (PQntuples(r) == 0) {
        PQclear(r);
        return err(400, "invalid_grant", "refresh token is not recognized");
    }
    const std::string family    = PQgetvalue(r, 0, 0);
    const std::string bound_cli = PQgetvalue(r, 0, 1);
    const std::string principal = PQgetvalue(r, 0, 2);
    const std::string scope     = PQgetvalue(r, 0, 3);
    const std::string resource  = PQgetvalue(r, 0, 4);
    const bool expired = std::string(PQgetvalue(r, 0, 5)) == "t";
    const bool rotated = std::string(PQgetvalue(r, 0, 6)) == "t";
    const bool revoked = std::string(PQgetvalue(r, 0, 7)) == "t";
    PQclear(r);

    if (bound_cli != client.client_id) {
        return err(400, "invalid_grant", "refresh token belongs to a different client");
    }
    if (revoked || expired) {
        return err(400, "invalid_grant", "refresh token is expired or revoked");
    }
    if (rotated) {
        // Presenting a rotated-out token = the classic theft signal (RFC
        // 9700). Someone — the thief or the victim — holds the successor;
        // revoke the entire family and force a fresh login.
        PGresult* rev = exec(
            "UPDATE gptimage.oauth_refresh_tokens SET revoked_at = now() "
            "WHERE family_id = $1::uuid AND revoked_at IS NULL",
            {family.c_str()});
        PQclear(rev);
        audit("refresh_reuse_detected", principal,
              {{"client_id", client.client_id}, {"family_id", family}});
        spdlog::warn("oauth: refresh-token REUSE for '{}' family {} — family revoked",
                     principal, family);
        return err(400, "invalid_grant", "refresh token reuse detected; family revoked");
    }

    // Principal must still resolve a grant — deleting the [[auth.principals]]
    // entry is the operator's kill switch and must sever refresh too.
    if (!grant_from_config(cfg_.auth, principal)) {
        return err(400, "invalid_grant", "principal is no longer configured");
    }

    // Rotate: retire this token, issue a successor in the same family.
    {
        PGresult* rot = exec(
            "UPDATE gptimage.oauth_refresh_tokens SET rotated_at = now() WHERE token_hash = $1",
            {token_hash.c_str()});
        PQclear(rot);
    }
    return issue_tokens(principal, client.client_id, scope, resource, family);
}

json OAuthService::issue_tokens(const std::string& principal,
                                const std::string& client_id,
                                const std::string& scope,
                                const std::string& resource,
                                std::string family) {
    const int64_t now = now_s();
    const std::string jti = new_uuid();
    const json claims{
        {"iss", cfg_.auth.jwt_issuer},
        {"aud", cfg_.auth.jwt_audience},
        {"sub", principal},
        {"client_id", client_id},
        {"scope", scope.empty() ? "mcp" : scope},
        {"iat", now},
        {"exp", now + cfg_.auth.oauth.access_token_ttl_s},
        {"jti", jti},
    };
    const std::string access = sign_jwt_rs256(active_key(), claims);

    if (family.empty()) family = new_uuid();
    const std::string refresh = random_token("rlqr_");
    const std::string refresh_hash = sha256_hex(refresh);
    const std::string ttl = std::to_string(cfg_.auth.oauth.refresh_token_ttl_s);
    const char* sql =
        "INSERT INTO gptimage.oauth_refresh_tokens "
        "(token_hash, family_id, client_id, principal, scope, resource, expires_at) "
        "VALUES ($1, $2::uuid, $3, $4, NULLIF($5,''), NULLIF($6,''), "
        "        now() + make_interval(secs => $7::int))";
    PGresult* r = exec(sql, {refresh_hash.c_str(), family.c_str(), client_id.c_str(),
                             principal.c_str(), scope.c_str(), resource.c_str(), ttl.c_str()});
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        // The access token already exists and is valid — losing rotation is
        // worse than losing this refresh insert, so surface loudly.
        spdlog::error("oauth: refresh insert failed: {}", PQerrorMessage(db().native()));
    }
    PQclear(r);

    audit("tokens_issued", principal,
          {{"client_id", client_id}, {"jti", jti}, {"family_id", family}});

    return json{
        {"access_token", access},
        {"token_type", "Bearer"},
        {"expires_in", cfg_.auth.oauth.access_token_ttl_s},
        {"refresh_token", refresh},
        {"scope", scope.empty() ? "mcp" : scope},
    };
}

}  // namespace gptimage
