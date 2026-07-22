#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace gptimage {

struct DatabaseConfig {
    std::string host = "127.0.0.1";
    uint16_t port = 5432;
    std::string dbname;
    std::string user;
    std::string password_env;
    std::string schema = "gptimage";
    // libpq sslmode, passed through verbatim when non-empty. Empty leaves it
    // unset (libpq defaults to "prefer"). Validated against the libpq value set
    // at load time.
    std::string sslmode;

    // Resolved from environment at load time. Empty if password_env unset.
    std::string password;
};

// [image] — the OpenAI image-generation backend. The whole point of the server:
// gptimage_generate / gptimage_edit call these endpoints with the caller's
// prompt and hand the base64 result straight back as an MCP image block.
struct ImageConfig {
    // Model id. gpt-image-2 is "ChatGPT Images 2.0". Bump here when OpenAI ships
    // the next one; nothing else needs to change.
    std::string model = "gpt-image-2";
    // Env var holding the OpenAI key. The key itself never lives in the TOML.
    std::string api_key_env = "OPENAI_API_KEY";
    std::string generations_endpoint = "https://api.openai.com/v1/images/generations";
    std::string edits_endpoint       = "https://api.openai.com/v1/images/edits";

    // Defaults applied when a tool call omits the field.
    std::string default_size       = "1024x1024";  // WxH (div by 16, 1:3..3:1) or "auto"
    std::string default_quality    = "high";        // auto|low|medium|high
    std::string default_background = "auto";        // transparent|opaque|auto
    std::string default_format     = "png";         // png|jpeg|webp
    std::string moderation         = "low";         // auto|low

    int max_n              = 4;    // hard cap on images per call (cost guard)
    int timeout_s          = 180;  // generation can be slow at high quality/2K
    int max_retries        = 4;    // on 429/5xx/network
    int backoff_initial_ms = 800;

    // Resolved from environment at load time. Empty ⇒ the tools return an error
    // result instead of calling out.
    std::string api_key;
};

struct McpConfig {
    std::string transport = "stdio";            // "stdio" | "tcp" (legacy) | "http"
    std::string tcp_bind  = "127.0.0.1:17718";
    // Streamable HTTP transport. Binds loopback — Caddy fronts it with TLS and
    // proxies https://gptimage.specterpoint.com/mcp here.
    std::string http_bind = "127.0.0.1:17718";
    // An inline image round-trips as base64 in the JSON-RPC response; generated
    // images are large, so the body cap is generous compared with a text server.
    int  http_max_body_bytes  = 32 << 20;       // 413 above this (32 MiB)
    int  http_read_timeout_s  = 30;
    int  http_write_timeout_s = 200;            // gpt-image-2 high/2K is slow
};

// One configured principal: the mint-time template for static API tokens and
// the grant source for JWT-authenticated callers. Realm names may include "*"
// (wildcard read/write-all). Realm scoping is unused by the image tools but the
// grant machinery is shared verbatim with the auth/OAuth layer.
struct AuthPrincipalConfig {
    std::string              name;
    std::string              home_realm;
    std::vector<std::string> read_realms;
    std::vector<std::string> write_realms;
    std::string              max_sensitivity;
};

// [auth.oauth] — the embedded OAuth 2.1 authorization server (the login page
// claude.ai / ChatGPT connectors land on). Off by default: a box that only runs
// stdio or static-token HTTP never loads a signing key.
struct OAuthConfig {
    bool        enabled = false;
    // Issuer/base URL, e.g. "https://gptimage.specterpoint.com" — no trailing
    // slash. Also the RFC 8414 metadata `issuer`.
    std::string issuer;
    // Canonical protected resource (RFC 8707), e.g. issuer + "/mcp". Minted
    // access tokens carry this as `aud`.
    std::string resource;
    // RS256 signing key (PEM, private). previous_key_paths keeps rotated-out
    // keys in the published JWKS until their tokens age out.
    std::string              signing_key_path;
    std::vector<std::string> previous_key_paths;
    // Registered redirect URIs must be https and their host must equal or be a
    // subdomain of an entry here. Empty list = allow any host (discouraged).
    std::vector<std::string> redirect_hosts =
        {"claude.ai", "claude.com", "chatgpt.com", "openai.com"};
    // Access tokens have no revocation store (jti is minted, not checked), so
    // the TTL is the only bound on a leaked token — keep it short. Refresh
    // tokens (30 d, sliding) carry longevity; clients refresh transparently.
    int access_token_ttl_s  = 900;      // 15 min
    int auth_code_ttl_s     = 600;      // 10 min
    int refresh_token_ttl_s = 2592000;  // 30 d, sliding on rotation
    int max_clients         = 50;       // DCR cap
};

struct AuthConfig {
    // Only consulted for transport="http"; stdio/tcp trust the OS boundary and
    // always run as the local operator.
    bool                             enabled = true;
    std::vector<AuthPrincipalConfig> principals;
    // Emitted in WWW-Authenticate and served at the
    // /.well-known/oauth-protected-resource route when set.
    std::string                      resource_metadata_url;
    // JWT validation. When [auth.oauth] is enabled and these are empty they are
    // derived from oauth.issuer/oauth.resource at load time, so the mint and
    // verify sides cannot drift.
    std::string                      jwt_issuer;
    std::string                      jwt_audience;
    std::string                      jwt_jwks_url;
    std::string                      jwt_principal_claim = "sub";
    // (claim value -> principal name) overrides, for when the JWT subject is a
    // UUID rather than a friendly principal name.
    std::vector<std::pair<std::string, std::string>> jwt_subject_map;
    OAuthConfig                      oauth;
};

struct LoggingConfig {
    std::string level = "info";
    std::string path;
    int rotate_mb = 25;
    int retain_files = 10;
};

struct Config {
    DatabaseConfig database;
    ImageConfig    image;
    McpConfig      mcp;
    AuthConfig     auth;
    LoggingConfig  logging;
};

// Parses a TOML config file and resolves *_env fields from the environment.
// Required fields: database.dbname, database.user. Missing env vars referenced
// by password_env / api_key_env are tolerated (left empty) but validated before
// use.
Config load_config(const std::filesystem::path& path);

// $GPTIMAGE_CONFIG if set, else "config/gptimage.toml" under CWD.
std::filesystem::path default_config_path();

}  // namespace gptimage
