#include <gptimage/auth.hpp>
#include <gptimage/config.hpp>
#include <gptimage/db.hpp>
#include <gptimage/realm.hpp>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace gptimage {

using nlohmann::json;

namespace {

void print_usage() {
    std::fprintf(stderr,
        "gptimage_cli tokens <add|list|revoke> [args]\n"
        "\n"
        "  add --principal <name> [--home <realm>] [--read a,b] [--write a,b]\n"
        "      [--max-sensitivity low|medium|high|restricted] [--note <text>]\n"
        "        Mint a bearer token. With no grant flags, the grant comes from the\n"
        "        [[auth.principals]] entry named <name>. The plaintext token is printed\n"
        "        ONCE — store it now; only its hash is kept.\n"
        "  list\n"
        "        List tokens (hash prefix, principal, enabled, last used, note).\n"
        "  revoke --prefix <hex>\n"
        "        Disable the token whose hash starts with <prefix> (must be unique).\n");
}

std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        // trim spaces
        size_t a = item.find_first_not_of(" \t");
        size_t b = item.find_last_not_of(" \t");
        if (a != std::string::npos) out.push_back(item.substr(a, b - a + 1));
    }
    return out;
}

void apply_list(const std::vector<std::string>& in, bool& all, std::vector<std::string>& out) {
    all = false; out.clear();
    for (const auto& r : in) { if (r == "*") { all = true; out.clear(); return; } out.push_back(r); }
}

json grant_to_json(const RealmGrant& g) {
    json j;
    j["home"]  = g.home_realm;
    j["read"]  = g.read_all  ? json::array({"*"}) : json(g.read_realms);
    j["write"] = g.write_all ? json::array({"*"}) : json(g.write_realms);
    if (!g.max_sensitivity.empty()) j["max_sensitivity"] = g.max_sensitivity;
    return j;
}

// Collect every concrete (non-wildcard) realm a grant references.
std::vector<std::string> referenced_realms(const RealmGrant& g) {
    std::vector<std::string> all;
    if (!g.home_realm.empty()) all.push_back(g.home_realm);
    if (!g.read_all)  for (auto& r : g.read_realms)  all.push_back(r);
    if (!g.write_all) for (auto& r : g.write_realms) all.push_back(r);
    return all;
}

// Returns the first realm in `names` that does not exist in gptimage.realms,
// or empty string if all exist.
std::string first_unknown_realm(DbConn& db, const std::vector<std::string>& names) {
    for (const auto& n : names) {
        const char* sql = "SELECT 1 FROM gptimage.realms WHERE name = $1";
        const char* params[] = { n.c_str() };
        PGresult* r = PQexecParams(db.native(), sql, 1, nullptr, params, nullptr, nullptr, 0);
        const bool exists = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;
        PQclear(r);
        if (!exists) return n;
    }
    return {};
}

int cmd_add(const Config& cfg, const std::vector<std::string>& args) {
    std::string principal, home, read_csv, write_csv, max_sens, note;
    bool have_grant_flags = false;
    for (size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        auto next = [&](std::string& dst) { if (i + 1 < args.size()) dst = args[++i]; };
        if      (a == "--principal") next(principal);
        else if (a == "--home")  { next(home);  have_grant_flags = true; }
        else if (a == "--read")  { next(read_csv);  have_grant_flags = true; }
        else if (a == "--write") { next(write_csv); have_grant_flags = true; }
        else if (a == "--max-sensitivity") { next(max_sens); have_grant_flags = true; }
        else if (a == "--note")  next(note);
    }
    if (principal.empty()) {
        std::fprintf(stderr, "tokens add: --principal required\n");
        return 1;
    }

    RealmGrant grant;
    if (have_grant_flags) {
        if (home.empty()) {
            std::fprintf(stderr, "tokens add: --home required when grant flags are given\n");
            return 1;
        }
        grant.principal       = principal;
        grant.home_realm      = home;
        grant.max_sensitivity = max_sens;
        apply_list(split_csv(read_csv),  grant.read_all,  grant.read_realms);
        apply_list(split_csv(write_csv), grant.write_all, grant.write_realms);
    } else {
        auto from_cfg = grant_from_config(cfg.auth, principal);
        if (!from_cfg) {
            std::fprintf(stderr,
                "tokens add: no [[auth.principals]] template named '%s' and no grant "
                "flags given (--home/--read/--write)\n", principal.c_str());
            return 1;
        }
        grant = *from_cfg;
    }

    DbConn db(cfg.database);
    if (auto bad = first_unknown_realm(db, referenced_realms(grant)); !bad.empty()) {
        std::fprintf(stderr, "tokens add: realm '%s' does not exist in gptimage.realms\n",
                     bad.c_str());
        return 1;
    }

    const std::string token = generate_token();
    const std::string hash  = sha256_hex(token);
    const std::string grants_str = grant_to_json(grant).dump();

    const char* sql =
        "INSERT INTO gptimage.api_tokens (token_hash, principal, grants, note) "
        "VALUES ($1, $2, $3::jsonb, $4)";
    const char* params[] = { hash.c_str(), principal.c_str(), grants_str.c_str(),
                             note.empty() ? nullptr : note.c_str() };
    PGresult* r = PQexecParams(db.native(), sql, 4, nullptr, params, nullptr, nullptr, 0);
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        std::fprintf(stderr, "tokens add: insert failed: %s\n", PQerrorMessage(db.native()));
        PQclear(r);
        return 1;
    }
    PQclear(r);

    std::printf(
        "Token minted for principal '%s'.\n"
        "  STORE THIS NOW — it is shown once and only the hash is kept:\n\n"
        "    %s\n\n"
        "  grants: %s\n", principal.c_str(), token.c_str(), grants_str.c_str());
    return 0;
}

int cmd_list(const Config& cfg) {
    DbConn db(cfg.database);
    const char* sql =
        "SELECT left(token_hash,8), principal, enabled::text, "
        "       created_at::date::text, coalesce(last_used_at::date::text,'never'), "
        "       coalesce(note,'') "
        "FROM gptimage.api_tokens ORDER BY created_at";
    PGresult* r = PQexec(db.native(), sql);
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        std::fprintf(stderr, "tokens list: %s\n", PQerrorMessage(db.native()));
        PQclear(r);
        return 1;
    }
    const int n = PQntuples(r);
    std::printf("%-10s %-12s %-8s %-12s %-12s %s\n",
                "HASH", "PRINCIPAL", "ENABLED", "CREATED", "LAST USED", "NOTE");
    for (int i = 0; i < n; ++i) {
        std::printf("%-10s %-12s %-8s %-12s %-12s %s\n",
                    PQgetvalue(r, i, 0), PQgetvalue(r, i, 1),
                    std::string(PQgetvalue(r, i, 2)) == "t" ? "yes" : "NO",
                    PQgetvalue(r, i, 3), PQgetvalue(r, i, 4), PQgetvalue(r, i, 5));
    }
    PQclear(r);
    std::printf("(%d token%s)\n", n, n == 1 ? "" : "s");
    return 0;
}

int cmd_revoke(const Config& cfg, const std::vector<std::string>& args) {
    std::string prefix;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--prefix" && i + 1 < args.size()) prefix = args[++i];
    }
    if (prefix.size() < 6) {
        std::fprintf(stderr, "tokens revoke: --prefix must be at least 6 hex chars\n");
        return 1;
    }
    DbConn db(cfg.database);
    const std::string pattern = prefix + "%";
    const char* csql = "SELECT count(*) FROM gptimage.api_tokens WHERE token_hash LIKE $1";
    const char* cparams[] = { pattern.c_str() };
    PGresult* cr = PQexecParams(db.native(), csql, 1, nullptr, cparams, nullptr, nullptr, 0);
    if (PQresultStatus(cr) != PGRES_TUPLES_OK) {
        std::fprintf(stderr, "tokens revoke: %s\n", PQerrorMessage(db.native()));
        PQclear(cr);
        return 1;
    }
    const int matches = std::atoi(PQgetvalue(cr, 0, 0));
    PQclear(cr);
    if (matches == 0) { std::fprintf(stderr, "tokens revoke: no token matches prefix '%s'\n", prefix.c_str()); return 1; }
    if (matches > 1)  { std::fprintf(stderr, "tokens revoke: prefix '%s' matches %d tokens — be more specific\n", prefix.c_str(), matches); return 1; }

    const char* usql = "UPDATE gptimage.api_tokens SET enabled = FALSE WHERE token_hash LIKE $1";
    PGresult* ur = PQexecParams(db.native(), usql, 1, nullptr, cparams, nullptr, nullptr, 0);
    const bool ok = PQresultStatus(ur) == PGRES_COMMAND_OK;
    if (!ok) std::fprintf(stderr, "tokens revoke: %s\n", PQerrorMessage(db.native()));
    PQclear(ur);
    if (ok) std::printf("revoked token %s\n", prefix.c_str());
    return ok ? 0 : 1;
}

}  // namespace

int cmd_tokens(const Config& cfg, std::vector<std::string> args) {
    if (args.empty() || args[0] == "-h" || args[0] == "--help") {
        print_usage();
        return args.empty() ? 1 : 0;
    }
    const std::string sub = args[0];
    std::vector<std::string> rest(args.begin() + 1, args.end());
    if (sub == "add")    return cmd_add(cfg, rest);
    if (sub == "list")   return cmd_list(cfg);
    if (sub == "revoke") return cmd_revoke(cfg, rest);
    std::fprintf(stderr, "tokens: unknown subcommand '%s'\n", sub.c_str());
    print_usage();
    return 1;
}

}  // namespace gptimage
