#include <gptimage/config.hpp>
#include <gptimage/db.hpp>
#include <gptimage/jwt_sign.hpp>

#include <libpq-fe.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#ifndef _WIN32
#  include <sys/stat.h>
#endif

namespace gptimage {

namespace {

void print_usage() {
    std::fprintf(stderr,
        "gptimage_cli oauth <keygen|clients> [args]\n"
        "\n"
        "  keygen [--out <path>] [--bits 2048] [--force]\n"
        "        Generate the RS256 signing key for the embedded authorization\n"
        "        server. Default --out is auth.oauth.signing_key_path from config.\n"
        "        Refuses to overwrite an existing key without --force (rotating\n"
        "        means: new key at signing_key_path, old key appended to\n"
        "        previous_key_paths — never clobber in place).\n"
        "  clients list\n"
        "        List dynamically-registered OAuth clients.\n"
        "  clients prune [--days 90]\n"
        "        Delete clients with no live refresh token that are older than\n"
        "        --days. claude.ai/ChatGPT re-register on the next connect.\n");
}

int cmd_keygen(const Config& cfg, const std::vector<std::string>& args) {
    std::string out_path = cfg.auth.oauth.signing_key_path;
    int bits = 2048;
    bool force = false;
    for (size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        if (a == "--out" && i + 1 < args.size())  out_path = args[++i];
        else if (a == "--bits" && i + 1 < args.size()) bits = std::stoi(args[++i]);
        else if (a == "--force") force = true;
    }
    if (out_path.empty()) {
        std::fprintf(stderr,
            "oauth keygen: no --out and auth.oauth.signing_key_path is unset\n");
        return 1;
    }
    if (bits < 2048) {
        std::fprintf(stderr, "oauth keygen: refusing < 2048-bit RSA\n");
        return 1;
    }
    if (std::filesystem::exists(out_path) && !force) {
        std::fprintf(stderr,
            "oauth keygen: %s already exists. Rotation = write the NEW key elsewhere,\n"
            "move the old path into auth.oauth.previous_key_paths, then swap. Use\n"
            "--force only if you really mean to destroy this key.\n",
            out_path.c_str());
        return 1;
    }

    const std::string pem = generate_rsa_key_pem(bits);

    {
        std::ofstream os(out_path, std::ios::binary | std::ios::trunc);
        if (!os) {
            std::fprintf(stderr, "oauth keygen: cannot write %s\n", out_path.c_str());
            return 1;
        }
        os << pem;
    }
#ifndef _WIN32
    // Private key: owner read/write only. On Windows the containing directory's
    // ACL is the boundary (ProgramData\GPTImage\credentials or /etc-equivalent).
    ::chmod(out_path.c_str(), 0600);
#endif

    const SigningKey key = SigningKey::load_pem(pem);
    std::printf("Wrote %d-bit RSA signing key to %s\n", bits, out_path.c_str());
    std::printf("kid: %s\n", key.kid().c_str());
    std::printf("public JWK: %s\n", key.public_jwk().dump(2).c_str());
    return 0;
}

int cmd_clients_list(const Config& cfg) {
    DbConn db(cfg.database);
    const char* sql =
        "SELECT c.client_id, coalesce(c.client_name,''), c.token_endpoint_auth, "
        "       c.created_at::text, coalesce(c.last_used_at::text,'never'), "
        "       (SELECT count(*) FROM gptimage.oauth_refresh_tokens t "
        "         WHERE t.client_id = c.client_id AND t.revoked_at IS NULL "
        "           AND t.rotated_at IS NULL AND t.expires_at > now()) AS live_tokens "
        "FROM gptimage.oauth_clients c ORDER BY c.created_at";
    PGresult* r = PQexec(db.native(), sql);
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        std::fprintf(stderr, "oauth clients list: %s\n", PQerrorMessage(db.native()));
        PQclear(r);
        return 1;
    }
    const int n = PQntuples(r);
    std::printf("%-30s %-24s %-20s %-25s %-25s %s\n",
                "client_id", "name", "auth", "created", "last used", "live tokens");
    for (int i = 0; i < n; ++i) {
        std::printf("%-30s %-24s %-20s %-25s %-25s %s\n",
                    PQgetvalue(r, i, 0), PQgetvalue(r, i, 1), PQgetvalue(r, i, 2),
                    PQgetvalue(r, i, 3), PQgetvalue(r, i, 4), PQgetvalue(r, i, 5));
    }
    if (n == 0) std::printf("(no registered clients)\n");
    PQclear(r);
    return 0;
}

int cmd_clients_prune(const Config& cfg, const std::vector<std::string>& args) {
    int days = 90;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--days" && i + 1 < args.size()) days = std::stoi(args[++i]);
    }
    DbConn db(cfg.database);
    // A client is prunable when it is old AND owns no refresh token that could
    // still rotate (live or merely un-expired). Codes cascade with the client.
    const std::string days_s = std::to_string(days);
    const char* sql =
        "DELETE FROM gptimage.oauth_clients c "
        "WHERE c.created_at < now() - make_interval(days => $1::int) "
        "  AND NOT EXISTS (SELECT 1 FROM gptimage.oauth_refresh_tokens t "
        "                   WHERE t.client_id = c.client_id "
        "                     AND t.revoked_at IS NULL AND t.expires_at > now())";
    const char* params[] = { days_s.c_str() };
    PGresult* r = PQexecParams(db.native(), sql, 1, nullptr, params, nullptr, nullptr, 0);
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        std::fprintf(stderr, "oauth clients prune: %s\n", PQerrorMessage(db.native()));
        PQclear(r);
        return 1;
    }
    std::printf("Pruned %s client(s) older than %d day(s) with no live tokens.\n",
                PQcmdTuples(r), days);
    PQclear(r);
    return 0;
}

}  // namespace

int cmd_oauth(const Config& cfg, std::vector<std::string> args) {
    if (args.empty()) {
        print_usage();
        return 1;
    }
    const std::string sub = args.front();
    args.erase(args.begin());

    if (sub == "keygen") return cmd_keygen(cfg, args);
    if (sub == "clients") {
        if (!args.empty() && args.front() == "list")  return cmd_clients_list(cfg);
        if (!args.empty() && args.front() == "prune") {
            args.erase(args.begin());
            return cmd_clients_prune(cfg, args);
        }
    }
    print_usage();
    return 1;
}

}  // namespace gptimage
