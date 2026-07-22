#include <gptimage/config.hpp>
#include <gptimage/db.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace gptimage {

namespace {

struct Migration {
    std::string name;
    fs::path    path;
    std::string sql;
};

std::string env_or_empty(const char* name) {
    if (!name) return {};
#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable : 4996)
#endif
    const char* v = std::getenv(name);
#ifdef _MSC_VER
#  pragma warning(pop)
#endif
    return v ? std::string(v) : std::string();
}

// Probe for the sql/migrations directory. Order:
//   1. $GPTIMAGE_MIGRATIONS_DIR
//   2. ./sql/migrations (relative to CWD)
fs::path find_migrations_dir() {
    auto env = env_or_empty("GPTIMAGE_MIGRATIONS_DIR");
    if (!env.empty()) return fs::path(env);
    return fs::path("sql") / "migrations";
}

void exec_or_throw(PGconn* c, const std::string& sql, const std::string& label) {
    PGresult* r = PQexec(c, sql.c_str());
    const auto status = PQresultStatus(r);
    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
        const std::string err = PQerrorMessage(c);
        PQclear(r);
        throw std::runtime_error(label + ": " + err);
    }
    PQclear(r);
}

void exec_params(PGconn* c,
                 const std::string& sql,
                 const std::vector<std::string>& params,
                 const std::string& label) {
    std::vector<const char*> pv;
    pv.reserve(params.size());
    for (const auto& p : params) pv.push_back(p.c_str());
    PGresult* r = PQexecParams(
        c, sql.c_str(),
        static_cast<int>(pv.size()),
        /*paramTypes=*/nullptr, pv.data(),
        /*paramLengths=*/nullptr, /*paramFormats=*/nullptr,
        /*resultFormat=*/0);
    const auto status = PQresultStatus(r);
    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
        const std::string err = PQerrorMessage(c);
        PQclear(r);
        throw std::runtime_error(label + ": " + err);
    }
    PQclear(r);
}

std::unordered_set<std::string> list_applied(PGconn* c, const std::string& schema) {
    std::unordered_set<std::string> out;
    const std::string sql = "SELECT name FROM " + schema + ".schema_migrations";
    PGresult* r = PQexec(c, sql.c_str());
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        const std::string err = PQerrorMessage(c);
        PQclear(r);
        throw std::runtime_error("list_applied: " + err);
    }
    const int n = PQntuples(r);
    for (int i = 0; i < n; ++i) out.emplace(PQgetvalue(r, i, 0));
    PQclear(r);
    return out;
}

std::string read_file(const fs::path& p) {
    std::ifstream is(p, std::ios::binary);
    if (!is) throw std::runtime_error("cannot read " + p.string());
    std::ostringstream os;
    os << is.rdbuf();
    return os.str();
}

std::vector<Migration> discover(const fs::path& dir) {
    if (!fs::exists(dir)) {
        throw std::runtime_error(
            "migrations directory not found: " + dir.string() +
            " (set GPTIMAGE_MIGRATIONS_DIR or cd to project root)");
    }
    std::vector<Migration> out;
    for (const auto& e : fs::directory_iterator(dir)) {
        if (!e.is_regular_file()) continue;
        if (e.path().extension() != ".sql") continue;
        Migration m;
        m.name = e.path().stem().string();
        m.path = e.path();
        out.push_back(std::move(m));
    }
    std::sort(out.begin(), out.end(),
              [](const Migration& a, const Migration& b) { return a.name < b.name; });
    for (auto& m : out) m.sql = read_file(m.path);
    return out;
}

}  // namespace

int cmd_migrate(const Config& cfg, std::vector<std::string> /*args*/) {
    DbConn conn(cfg.database);
    auto* c = conn.native();

    // Bootstrap: ensure the schema and tracking table exist so we can read
    // the list of applied migrations. The migrations themselves will also
    // re-assert the schema with CREATE SCHEMA IF NOT EXISTS — that's fine.
    exec_or_throw(c, "CREATE SCHEMA IF NOT EXISTS " + cfg.database.schema,
                  "ensure schema");
    exec_or_throw(c,
        "CREATE TABLE IF NOT EXISTS " + cfg.database.schema + ".schema_migrations ("
        "  name TEXT PRIMARY KEY,"
        "  applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        "ensure schema_migrations");

    const auto applied = list_applied(c, cfg.database.schema);
    const auto dir = find_migrations_dir();
    const auto migrations = discover(dir);

    int applied_count = 0;
    int skipped_count = 0;
    for (const auto& m : migrations) {
        if (applied.count(m.name)) {
            std::printf("  already applied: %s\n", m.name.c_str());
            ++skipped_count;
            continue;
        }
        std::printf("applying %s...\n", m.name.c_str());
        try {
            exec_or_throw(c, "BEGIN", "BEGIN");
            exec_or_throw(c, m.sql, m.name);
            exec_params(c,
                "INSERT INTO " + cfg.database.schema +
                ".schema_migrations (name) VALUES ($1)",
                {m.name},
                "record " + m.name);
            exec_or_throw(c, "COMMIT", "COMMIT");
            ++applied_count;
        } catch (const std::exception& e) {
            (void)PQexec(c, "ROLLBACK");  // best-effort
            std::fprintf(stderr, "  failed: %s\n", e.what());
            return 1;
        }
    }
    std::printf("done. applied=%d skipped=%d total=%zu\n",
                applied_count, skipped_count, migrations.size());
    return 0;
}

}  // namespace gptimage
