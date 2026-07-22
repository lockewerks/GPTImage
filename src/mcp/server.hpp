#pragma once

#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

#include <gptimage/config.hpp>
#include <gptimage/db.hpp>
#include <gptimage/jwt_sign.hpp>
#include <gptimage/jwt_verify.hpp>
#include <gptimage/realm.hpp>

#include <string>
#include <vector>

#include "oauth.hpp"

namespace gptimage {

// MCP server — JSON-RPC 2.0 dispatcher. Transport is either stdio (one JSON
// object per line on stdin, responses on stdout) or a loopback TCP socket.
// Scope in v1: initialize / tools/list / tools/call / ping. No resources,
// prompts, or sampling.
//
// The DB connection is lazy: a failed Postgres connect at startup would
// otherwise break the initialize / tools/list handshake Claude Desktop issues
// before any tool call. Only auth (static-token lookup) and /healthz touch it;
// the image tools call OpenAI and need no database.
class McpServer {
public:
    explicit McpServer(Config cfg);

    int run_stdio();
    int run_tcp(const std::string& bind);
    int run_http();

    // Process a single request-body line and return the serialized response
    // (empty if the request was a notification). Used by both transports and
    // integration tests. The no-grant overload uses local_grant() — the stdio
    // and loopback transports trust the OS boundary; the HTTP transport calls
    // the grant overload with the principal resolved from the bearer/JWT.
    std::string handle_line(const std::string& request_body);
    std::string handle_line(const std::string& request_body, const RealmGrant& grant);

    // Serializes request execution. The server holds a single DbConn + embedder
    // (no pool yet — see db.hpp), so concurrent HTTP requests must not overlap.
    // stdio is single-threaded and never contends.
    std::mutex& exec_mutex() { return exec_mtx_; }

    // Lightweight DB liveness check for /healthz. Returns false on any failure.
    bool db_healthy();

    // Whether `version` is an MCP protocol version this server speaks.
    static bool is_supported_protocol(const std::string& version);

private:
    nlohmann::json dispatch(const std::string& method, const nlohmann::json& params,
                            const RealmGrant& grant);

    nlohmann::json handle_initialize(const nlohmann::json& params);
    nlohmann::json handle_tools_list();
    nlohmann::json handle_tools_call(const nlohmann::json& params, const RealmGrant& grant);
    nlohmann::json handle_ping();

    DbConn&          ensure_db();

    static nlohmann::json respond_ok(const nlohmann::json& id, nlohmann::json result);
    static nlohmann::json respond_err(const nlohmann::json& id, int code,
                                       const std::string& message);

    Config                           cfg_;
    std::unique_ptr<DbConn>          db_;
    std::mutex                       exec_mtx_;

    // OAuth/JWT state, populated by run_http() when [auth.oauth] is enabled
    // and the signing key loads. Keys are shared with the verifier's local
    // JWKS fetcher (no HTTP self-fetch) and, later, the OAuth endpoints. A
    // load failure leaves both null: JWT auth and the OAuth routes stay off
    // while static tokens and /healthz keep the surface alive (fail closed
    // without killing the working parts).
    std::shared_ptr<const std::vector<SigningKey>> oauth_keys_;
    std::unique_ptr<JwtVerifier>                   jwt_verifier_;
    std::unique_ptr<OAuthService>                  oauth_;
};

}  // namespace gptimage
