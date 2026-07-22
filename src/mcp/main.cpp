#include "server.hpp"

#include <gptimage/config.hpp>

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <cstdio>
#include <exception>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

namespace {

void print_usage() {
    std::fprintf(stderr,
        "gptimage_mcp [--transport stdio|http|tcp]\n"
        "\n"
        "  --transport stdio   (default) JSON-RPC 2.0 over stdin/stdout — for Claude Desktop.\n"
        "  --transport http    MCP Streamable HTTP on [mcp].http_bind — remote endpoint.\n"
        "  --transport tcp     Loopback stub (unimplemented).\n"
        "\n"
        "  With no flag, the transport comes from [mcp].transport in the config.\n"
        "\n"
        "Env:\n"
        "  GPTIMAGE_CONFIG       config file (default: ./config/gptimage.toml)\n"
        "  GPTIMAGE_DB_PASSWORD  Postgres password (referenced by database.password_env)\n"
        "  OPENAI_API_KEY        image generation key (referenced by image.api_key_env)\n");
}

// stdio: stdout is the JSON-RPC wire, so logs go to stderr ONLY. http/tcp are
// free to log anywhere; we add an optional rotating file (mirrors the ingest
// daemon) and keep stderr for journald. Honors cfg.logging.level.
void setup_logging(const gptimage::Config& cfg, const std::string& transport) {
    try {
        std::vector<spdlog::sink_ptr> sinks;
        sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
        if (transport != "stdio" && !cfg.logging.path.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(cfg.logging.path, ec);
            const auto log_file = std::filesystem::path(cfg.logging.path) / "mcp.log";
            const auto max_bytes = static_cast<size_t>(cfg.logging.rotate_mb) * 1024u * 1024u;
            sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                log_file.string(), max_bytes, static_cast<size_t>(cfg.logging.retain_files)));
        }
        auto logger = std::make_shared<spdlog::logger>("gptimage_mcp", sinks.begin(), sinks.end());
        spdlog::set_default_logger(logger);
    } catch (const spdlog::spdlog_ex&) {
        // Fall back to whatever default exists rather than fail to start.
    }
    auto level = spdlog::level::info;
    const auto& lv = cfg.logging.level;
    if      (lv == "trace")    level = spdlog::level::trace;
    else if (lv == "debug")    level = spdlog::level::debug;
    else if (lv == "warn")     level = spdlog::level::warn;
    else if (lv == "error")    level = spdlog::level::err;
    else if (lv == "critical") level = spdlog::level::critical;
    spdlog::set_level(level);
}

}  // namespace

int main(int argc, char** argv) {
    std::string transport;  // empty => take from config
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-h" || a == "--help") {
            print_usage();
            return 0;
        }
        if (a == "--transport" && i + 1 < argc) {
            transport = argv[++i];
        }
    }

    gptimage::Config cfg;
    try {
        cfg = gptimage::load_config(gptimage::default_config_path());
    } catch (const std::exception& e) {
        std::fprintf(stderr, "config error: %s\n", e.what());
        return 2;
    }

    if (transport.empty()) transport = cfg.mcp.transport;

    setup_logging(cfg, transport);

    // Capture bind strings before cfg is moved into the server.
    const std::string tcp_bind = cfg.mcp.tcp_bind;

    gptimage::McpServer server(std::move(cfg));
    if (transport == "stdio") return server.run_stdio();
    if (transport == "http")  return server.run_http();
    if (transport == "tcp")   return server.run_tcp(tcp_bind);

    std::fprintf(stderr, "unknown transport: %s\n", transport.c_str());
    print_usage();
    return 2;
}
