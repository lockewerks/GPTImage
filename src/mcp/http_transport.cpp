// Streamable HTTP transport for the MCP server. Binds loopback; Caddy fronts
// it with TLS and proxies https://gptimage.specterpoint.com/mcp here.
//
// Endpoints:
//   POST /mcp        JSON-RPC request -> response (202 for notification-only)
//   GET  /mcp        405 (no server-initiated SSE stream in this build)
//   GET  /healthz    unauthenticated liveness + DB check, for probes
//
// Concurrency: the server holds one DbConn + embedder, so request execution is
// serialized under exec_mutex(). At two principals and low QPS this is fine; a
// connection pool (db.hpp) is the upgrade when it isn't.

#include "server.hpp"
#include "auth.hpp"

#include <gptimage/image_client.hpp>
#include <gptimage/realm.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <exception>
#include <mutex>
#include <string>
#include <thread>

namespace gptimage {

using nlohmann::json;

namespace {

// Set by SIGINT/SIGTERM; a watcher thread polls it and stops the server.
// Non-capturing handlers can only touch namespace-scope state.
std::atomic<bool> g_http_stop{false};
void on_stop_signal(int) { g_http_stop = true; }

std::string jsonrpc_error(const json& id, int code, const std::string& message) {
    return json{
        {"jsonrpc", "2.0"},
        {"id", id},
        {"error", {{"code", code}, {"message", message}}},
    }.dump();
}

bool parse_bind(const std::string& bind, std::string& host, int& port) {
    const auto pos = bind.rfind(':');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= bind.size()) return false;
    host = bind.substr(0, pos);
    try {
        port = std::stoi(bind.substr(pos + 1));
    } catch (const std::exception&) {
        return false;
    }
    return port > 0 && port < 65536;
}

bool header_contains(const httplib::Request& req, const char* name, const char* needle) {
    const std::string v = req.get_header_value(name);
    return v.find(needle) != std::string::npos;
}

}  // namespace

int McpServer::run_http() {
    std::string host;
    int port = 0;
    if (!parse_bind(cfg_.mcp.http_bind, host, port)) {
        spdlog::error("http: invalid mcp.http_bind '{}' (want host:port)", cfg_.mcp.http_bind);
        return 2;
    }
    if (host != "127.0.0.1" && host != "::1" && host != "localhost") {
        // Legitimate for a direct non-loopback bind, but loud: the design
        // expects Caddy in front terminating TLS + nothing else reachable.
        spdlog::warn("http: binding non-loopback host '{}' — ensure a TLS proxy "
                     "and firewall front this", host);
    }

    httplib::Server svr;
    svr.set_payload_max_length(static_cast<size_t>(cfg_.mcp.http_max_body_bytes));
    svr.set_read_timeout(cfg_.mcp.http_read_timeout_s, 0);
    svr.set_write_timeout(cfg_.mcp.http_write_timeout_s, 0);
    svr.set_keep_alive_max_count(64);

    // ---- JWT verification wiring -------------------------------------------
    // Self-issued tokens verify against the locally-loaded signing keys via an
    // injected fetcher — no HTTP round-trip to our own /.well-known/jwks.json.
    // The "local:oauth-signing" URL is only the verifier's cache key.
    if (cfg_.auth.oauth.enabled) {
        try {
            auto keys = std::make_shared<std::vector<SigningKey>>();
            keys->push_back(SigningKey::load_pem_file(cfg_.auth.oauth.signing_key_path));
            for (const auto& p : cfg_.auth.oauth.previous_key_paths) {
                keys->push_back(SigningKey::load_pem_file(p));
            }
            const std::string jwks_doc = jwks_json(*keys).dump();
            jwt_verifier_ = std::make_unique<JwtVerifier>(
                cfg_.auth.jwt_issuer, cfg_.auth.jwt_audience, "local:oauth-signing",
                [jwks_doc](const std::string&) { return jwks_doc; });
            oauth_keys_ = std::move(keys);
            oauth_ = std::make_unique<OAuthService>(cfg_, oauth_keys_);
            register_oauth_routes(svr, *oauth_, cfg_);
            spdlog::info("oauth: AS endpoints + JWT auth active (issuer {}, kid {})",
                         cfg_.auth.jwt_issuer, oauth_keys_->front().kid());
        } catch (const std::exception& e) {
            // Fail closed without killing the working surface: no OAuth
            // routes, no JWT auth — static gpt_ tokens and /healthz survive.
            spdlog::error("oauth: signing key load failed: {}", e.what());
            spdlog::error("oauth: OAuth endpoints and JWT auth are DISABLED for this run");
            oauth_keys_.reset();
            jwt_verifier_.reset();
        }
    } else if (!cfg_.auth.jwt_issuer.empty() && !cfg_.auth.jwt_jwks_url.empty()) {
        // External-issuer escape hatch: verify JWTs minted elsewhere against a
        // remote JWKS (the original Keycloak-shaped path). Unused by the
        // embedded AS but harmless to keep wired.
        jwt_verifier_ = std::make_unique<JwtVerifier>(
            cfg_.auth.jwt_issuer, cfg_.auth.jwt_audience, cfg_.auth.jwt_jwks_url);
        spdlog::info("auth: JWT auth active against external JWKS {}", cfg_.auth.jwt_jwks_url);
    }

    const bool auth_enabled = cfg_.auth.enabled;
    const std::string www_auth =
        cfg_.auth.resource_metadata_url.empty()
            ? std::string("Bearer")
            : "Bearer resource_metadata=\"" + cfg_.auth.resource_metadata_url + "\"";

    // ---- POST /mcp ----------------------------------------------------------
    svr.Post("/mcp", [this, auth_enabled, www_auth](const httplib::Request& req,
                                                    httplib::Response& res) {
        const auto t0 = std::chrono::steady_clock::now();

        if (!header_contains(req, "Content-Type", "application/json")) {
            res.status = 415;
            res.set_content(jsonrpc_error(nullptr, -32700, "Content-Type must be application/json"),
                            "application/json");
            return;
        }
        // Reject an unsupported explicit protocol-version header. Absent is fine
        // (header-less clients assume the spec default).
        const std::string pv = req.get_header_value("MCP-Protocol-Version");
        if (!pv.empty() && !is_supported_protocol(pv)) {
            res.status = 400;
            res.set_content(jsonrpc_error(nullptr, -32600, "unsupported MCP-Protocol-Version: " + pv),
                            "application/json");
            return;
        }
        // Reject pathologically nested JSON before parsing — nlohmann's
        // recursive parser can stack-overflow within the 1 MiB body cap.
        if (!json_within_depth(req.body, 64)) {
            res.status = 400;
            res.set_content(jsonrpc_error(nullptr, -32700, "request nesting too deep"),
                            "application/json");
            return;
        }

        // Auth + execution serialize on the single DbConn/embedder.
        std::lock_guard<std::mutex> lk(exec_mtx_);

        RealmGrant grant = local_grant();
        std::string principal = "local";
        if (auth_enabled) {
            AuthResult ar = authenticate(req.get_header_value("Authorization"), ensure_db(),
                                         cfg_, jwt_verifier_.get());
            if (!ar.ok) {
                spdlog::warn("http: 401 {} ({})", req.path, ar.error);
                res.status = 401;
                res.set_header("WWW-Authenticate", www_auth);
                res.set_content(jsonrpc_error(nullptr, -32001, "unauthorized"), "application/json");
                return;
            }
            grant = std::move(ar.grant);
            principal = grant.principal;
        }

        // Body may be a single JSON-RPC object or (older clients) an array.
        std::string response;
        json parsed = json::parse(req.body, nullptr, /*allow_exceptions=*/false);
        if (parsed.is_array()) {
            json batch = json::array();
            for (const auto& el : parsed) {
                const std::string r = handle_line(el.dump(), grant);
                if (!r.empty()) batch.push_back(json::parse(r));
            }
            response = batch.empty() ? std::string() : batch.dump();
        } else {
            // handle_line parses + shapes its own JSON-RPC errors.
            response = handle_line(req.body, grant);
        }

        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0).count();
        if (response.empty()) {
            res.status = 202;  // notification(s) only — nothing to return
        } else {
            res.status = 200;
            res.set_content(response, "application/json");
        }
        spdlog::info("http: POST /mcp {} principal={} {}ms", res.status, principal, ms);
    });

    // ---- GET/DELETE /mcp: no SSE stream, no sessions ------------------------
    auto method_not_allowed = [](const httplib::Request&, httplib::Response& res) {
        res.status = 405;
        res.set_header("Allow", "POST");
        res.set_content(jsonrpc_error(nullptr, -32600, "method not allowed; POST JSON-RPC to /mcp"),
                        "application/json");
    };
    svr.Get("/mcp", method_not_allowed);
    svr.Delete("/mcp", method_not_allowed);

    // ---- GET /i/<job_id>-<index>.<ext>: hosted render, unauthenticated ------
    // Lets the client render a generated image inline in the conversation body
    // (via the markdown link the tools return) instead of only inside the
    // collapsed tool-call block. Deliberately auth-free: claude.ai's image proxy
    // fetches this with no bearer token, so the 96-bit random job id is the
    // capability. It only ever serves an image the same caller's generate/edit
    // just produced, and the render is evicted from the in-memory cache minutes
    // after it completes (job_ttl_seconds) — nothing is persisted. Serves from
    // the JobStore's own lock, so it is not serialized behind exec_mtx_.
    svr.Get(R"(/i/(job_[0-9a-f]+)-(\d+)\.(?:png|jpe?g|webp))",
            [this](const httplib::Request& req, httplib::Response& res) {
        const std::string id = req.matches[1].str();
        size_t index = 0;
        try {
            index = static_cast<size_t>(std::stoul(req.matches[2].str()));
        } catch (const std::exception&) {
            res.status = 404;
            return;
        }
        auto img = jobs_.get_image(id, index);
        if (!img) {
            res.status = 404;
            res.set_content("image not found (expired, already released, or never existed)",
                            "text/plain");
            return;
        }
        const std::vector<unsigned char> bytes = base64_decode(img->b64);
        if (bytes.empty()) {
            res.status = 500;
            res.set_content("image decode error", "text/plain");
            return;
        }
        res.set_header("Cache-Control", "private, max-age=300");
        res.set_content(reinterpret_cast<const char*>(bytes.data()), bytes.size(), img->mime);
        spdlog::info("http: GET /i {}-{} {} bytes ({})", id, index, bytes.size(), img->mime);
    });

    // ---- GET /healthz: unauthenticated liveness -----------------------------
    svr.Get("/healthz", [this](const httplib::Request&, httplib::Response& res) {
        std::string db_state = "busy";
        std::unique_lock<std::mutex> lk(exec_mtx_, std::try_to_lock);
        if (lk.owns_lock()) {
            db_state = db_healthy() ? "ok" : "down";
        }
        const bool ok = db_state != "down";
        res.status = ok ? 200 : 503;
        res.set_content(json{{"status", ok ? "ok" : "degraded"}, {"db", db_state}}.dump(),
                        "application/json");
    });

    svr.set_exception_handler([](const httplib::Request&, httplib::Response& res,
                                 std::exception_ptr ep) {
        std::string what = "internal error";
        try { if (ep) std::rethrow_exception(ep); }
        catch (const std::exception& e) { what = e.what(); }
        catch (...) {}
        spdlog::error("http: unhandled exception: {}", what);
        res.status = 500;
        res.set_content(jsonrpc_error(nullptr, -32603, "internal error"), "application/json");
    });

    // Graceful shutdown: signal -> flag -> watcher stops the blocking listen().
    std::signal(SIGINT, on_stop_signal);
    std::signal(SIGTERM, on_stop_signal);
    std::thread watcher([&svr] {
        while (!g_http_stop) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        svr.stop();
    });

    spdlog::info("gptimage_mcp HTTP transport on {}:{} (auth {})",
                 host, port, auth_enabled ? "enabled" : "DISABLED");
    const bool listened = svr.listen(host, port);
    g_http_stop = true;  // ensure the watcher exits if listen() returned on its own
    watcher.join();

    if (!listened) {
        spdlog::error("http: failed to bind {}:{}", host, port);
        return 1;
    }
    spdlog::info("gptimage_mcp HTTP transport stopped");
    return 0;
}

}  // namespace gptimage
