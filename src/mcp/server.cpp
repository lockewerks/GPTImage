#include "server.hpp"
#include "tool_common.hpp"
#include "tools.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

namespace gptimage {

using nlohmann::json;

namespace {

// MCP protocol versions this server speaks. stdio Claude Desktop still sends
// "2024-11-05"; Streamable HTTP clients send a header and/or negotiate in
// initialize. We echo the client's version when supported, else the latest.
constexpr const char* kSupportedProtocols[] = {
    "2024-11-05", "2025-03-26", "2025-06-18",
};
constexpr const char* kLatestProtocol = "2025-06-18";
constexpr const char* kServerName     = "gptimage";
constexpr const char* kServerVersion  = "0.1.0";

}  // namespace

bool McpServer::is_supported_protocol(const std::string& version) {
    for (const char* v : kSupportedProtocols) {
        if (version == v) return true;
    }
    return false;
}

McpServer::McpServer(Config cfg) : cfg_(std::move(cfg)) {}

int McpServer::run_stdio() {
    // Block mixed stdio buffering and force per-line flush so responses land
    // on the client promptly.
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        const std::string resp = handle_line(line);
        if (!resp.empty()) {
            std::cout << resp << '\n';
            std::cout.flush();
        }
    }
    return 0;
}

int McpServer::run_tcp(const std::string& bind) {
    (void)bind;
    spdlog::error(
        "TCP transport not implemented in this build — use stdio or extend "
        "src/mcp/server.cpp run_tcp().");
    return 1;
}

std::string McpServer::handle_line(const std::string& body) {
    return handle_line(body, local_grant());
}

std::string McpServer::handle_line(const std::string& body, const RealmGrant& grant) {
    json req;
    try {
        req = json::parse(body);
    } catch (const json::exception& e) {
        return respond_err(nullptr, -32700,
                           std::string("parse error: ") + e.what()).dump();
    }

    const json id = req.contains("id") ? req["id"] : json(nullptr);
    const std::string method = req.value("method", std::string());
    const json params = req.value("params", json::object());
    const bool is_notification = !req.contains("id");

    try {
        json result = dispatch(method, params, grant);
        if (is_notification) return std::string();
        return respond_ok(id, std::move(result)).dump();
    } catch (const std::exception& e) {
        if (is_notification) return std::string();
        return respond_err(id, -32603, e.what()).dump();
    }
}

json McpServer::dispatch(const std::string& method, const json& params,
                         const RealmGrant& grant) {
    if (method == "initialize") return handle_initialize(params);
    if (method == "tools/list") return handle_tools_list();
    if (method == "tools/call") return handle_tools_call(params, grant);
    if (method == "ping")       return handle_ping();
    // Swallowed per MCP convention:
    if (method == "notifications/initialized") return json::object();
    throw std::runtime_error("method not found: " + method);
}

json McpServer::handle_initialize(const json& params) {
    // Version negotiation: echo the client's requested version if we speak it,
    // otherwise advertise our latest and let the client decide.
    std::string version = kLatestProtocol;
    if (params.contains("protocolVersion") && params["protocolVersion"].is_string()) {
        const std::string requested = params["protocolVersion"].get<std::string>();
        if (is_supported_protocol(requested)) version = requested;
    }
    return {
        {"protocolVersion", version},
        {"capabilities", {
            {"tools", json::object()},
        }},
        {"serverInfo", {
            {"name",    kServerName},
            {"version", kServerVersion},
        }},
    };
}

json McpServer::handle_tools_list() {
    return {{"tools", mcp_tool_schemas()}};
}

json McpServer::handle_tools_call(const json& params, const RealmGrant& grant) {
    const std::string name = params.value("name", std::string());
    const json arguments   = params.value("arguments", json::object());
    if (name.empty()) {
        throw std::runtime_error("tools/call: missing 'name'");
    }
    ToolContext ctx{cfg_, grant};
    return mcp_tool_call(name, arguments, ctx);
}

DbConn& McpServer::ensure_db() {
    if (!db_) db_ = std::make_unique<DbConn>(cfg_.database);
    return *db_;
}

bool McpServer::db_healthy() {
    try {
        PGresult* r = PQexec(ensure_db().native(), "SELECT 1");
        const bool ok = r && PQresultStatus(r) == PGRES_TUPLES_OK;
        if (r) PQclear(r);
        return ok;
    } catch (const std::exception&) {
        return false;
    }
}

json McpServer::handle_ping() {
    return json::object();
}

json McpServer::respond_ok(const json& id, json result) {
    return {
        {"jsonrpc", "2.0"},
        {"id",      id},
        {"result",  std::move(result)},
    };
}

json McpServer::respond_err(const json& id, int code, const std::string& message) {
    return {
        {"jsonrpc", "2.0"},
        {"id",      id},
        {"error",   {{"code", code}, {"message", message}}},
    };
}

}  // namespace gptimage
