#include <gptimage/config.hpp>

#include <cstdio>
#include <exception>
#include <string>
#include <vector>

namespace gptimage {
int cmd_migrate(const Config& cfg, std::vector<std::string> args);
int cmd_tokens(const Config& cfg, std::vector<std::string> args);
int cmd_passwd(const Config& cfg, std::vector<std::string> args);
int cmd_oauth(const Config& cfg, std::vector<std::string> args);
}  // namespace gptimage

namespace {

void print_usage() {
    std::fprintf(stderr,
        "gptimage_cli <command> [args]\n"
        "\n"
        "Commands:\n"
        "  migrate                 Apply pending schema migrations from sql/migrations/\n"
        "  tokens <add|list|revoke>  Manage HTTP bearer tokens (gpt_ static bearer)\n"
        "  passwd <principal>      Set the OAuth login password for a principal\n"
        "  oauth <keygen|clients>  Manage the embedded OAuth AS (signing key, clients)\n"
        "  -h, --help              Print this message\n"
        "\n"
        "Environment:\n"
        "  GPTIMAGE_CONFIG        Path to gptimage.toml (default: ./config/gptimage.toml)\n"
        "  GPTIMAGE_DB_PASSWORD   Postgres password referenced by config database.password_env\n"
        "  GPTIMAGE_MIGRATIONS_DIR  Override migrations directory (default: ./sql/migrations)\n");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }
    const std::string cmd = argv[1];
    if (cmd == "-h" || cmd == "--help") {
        print_usage();
        return 0;
    }

    gptimage::Config cfg;
    try {
        cfg = gptimage::load_config(gptimage::default_config_path());
    } catch (const std::exception& e) {
        std::fprintf(stderr, "config error: %s\n", e.what());
        return 2;
    }

    std::vector<std::string> args;
    args.reserve(static_cast<size_t>(argc - 2));
    for (int i = 2; i < argc; ++i) args.emplace_back(argv[i]);

    try {
        if (cmd == "migrate") return gptimage::cmd_migrate(cfg, std::move(args));
        if (cmd == "tokens")  return gptimage::cmd_tokens(cfg, std::move(args));
        if (cmd == "passwd")  return gptimage::cmd_passwd(cfg, std::move(args));
        if (cmd == "oauth")   return gptimage::cmd_oauth(cfg, std::move(args));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 3;
    }

    std::fprintf(stderr, "unknown command: %s\n\n", cmd.c_str());
    print_usage();
    return 1;
}
