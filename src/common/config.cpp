#include <gptimage/config.hpp>

#define TOML_EXCEPTIONS 1
#include <toml++/toml.hpp>

#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#  include <climits>
#endif

namespace gptimage {

namespace {

std::string env_or_empty(const char* name) {
    if (!name || !*name) return {};
    // MSVC deprecates std::getenv in favor of _dupenv_s; the POSIX API is still
    // standard C++ and thread-safe for read-only lookups of our own envvars.
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

// Absolute path to the running executable, or empty if the OS won't say. Used
// to find config relative to the binary instead of CWD.
std::filesystem::path current_exe_path() {
#ifdef _WIN32
    wchar_t buf[32768];  // long-path safe
    DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(sizeof(buf) / sizeof(buf[0])));
    if (n == 0 || n >= sizeof(buf) / sizeof(buf[0])) return {};
    return std::filesystem::path(buf);
#else
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    return std::filesystem::path(buf);
#endif
}

// Ordered candidate config paths, priority high to low:
//   1. $GPTIMAGE_CONFIG
//   2. <CWD>/config/gptimage.toml
//   3. walk up from <exe-dir>/config/gptimage.toml
//   4. %ProgramData%\GPTImage\gptimage.toml  (Windows installed layout)
std::vector<std::filesystem::path> candidate_config_paths() {
    std::vector<std::filesystem::path> out;
    if (auto p = env_or_empty("GPTIMAGE_CONFIG"); !p.empty()) {
        out.emplace_back(std::move(p));
    }
    out.push_back(std::filesystem::path("config") / "gptimage.toml");
    auto exe = current_exe_path();
    if (!exe.empty()) {
        auto dir = exe.parent_path();
        for (int i = 0; i < 8; ++i) {
            out.push_back(dir / "config" / "gptimage.toml");
            auto parent = dir.parent_path();
            if (parent == dir) break;
            dir = parent;
        }
    }
#ifdef _WIN32
    {
        std::string pd = env_or_empty("ProgramData");
        if (pd.empty()) pd = "C:\\ProgramData";
        out.push_back(std::filesystem::path(pd) / "GPTImage" / "gptimage.toml");
    }
#endif
    return out;
}

template <typename T>
T get_or(const toml::node_view<const toml::node>& nv, T fallback) {
    auto v = nv.value<T>();
    return v ? *v : fallback;
}

template <typename T>
T get_or(const toml::node_view<toml::node>& nv, T fallback) {
    auto v = nv.value<T>();
    return v ? *v : fallback;
}

bool valid_sslmode(const std::string& m) {
    return m.empty() || m == "disable" || m == "allow" || m == "prefer" ||
           m == "require" || m == "verify-ca" || m == "verify-full";
}

void parse_database_section(const toml::node_view<toml::node>& sec,
                            const char* label,
                            DatabaseConfig& cfg) {
    cfg.host         = get_or<std::string>(sec["host"],         "127.0.0.1");
    cfg.port         = static_cast<uint16_t>(get_or<int64_t>(sec["port"], 5432));
    cfg.dbname       = get_or<std::string>(sec["dbname"],       "");
    cfg.user         = get_or<std::string>(sec["user"],         "");
    cfg.password_env = get_or<std::string>(sec["password_env"], "");
    cfg.schema       = get_or<std::string>(sec["schema"],       "gptimage");
    cfg.sslmode      = get_or<std::string>(sec["sslmode"],      "");

    if (cfg.dbname.empty())
        throw std::runtime_error(std::string("config: ") + label + ".dbname required");
    if (cfg.user.empty())
        throw std::runtime_error(std::string("config: ") + label + ".user required");
    if (!valid_sslmode(cfg.sslmode))
        throw std::runtime_error(
            std::string("config: ") + label + ".sslmode invalid: '" + cfg.sslmode +
            "' (expected one of disable|allow|prefer|require|verify-ca|verify-full)");
    if (!cfg.password_env.empty())
        cfg.password = env_or_empty(cfg.password_env.c_str());
}

}  // namespace

Config load_config(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        std::string msg = "config file not found: " + path.string() + "\nSearched:";
        for (const auto& c : candidate_config_paths()) {
            msg += "\n  - " + c.string();
        }
        throw std::runtime_error(msg);
    }

    toml::table tbl;
    try {
        tbl = toml::parse_file(path.string());
    } catch (const toml::parse_error& e) {
        throw std::runtime_error(
            std::string("config parse error: ") + e.description().data());
    }

    Config cfg;

    // ----- [database] -----
    {
        auto sec = tbl["database"];
        if (!sec.is_table()) {
            throw std::runtime_error("config: [database] section required");
        }
        parse_database_section(sec, "database", cfg.database);
    }

    // ----- [image] -----
    if (auto sec = tbl["image"]; sec.is_table()) {
        cfg.image.model               = get_or<std::string>(sec["model"],               cfg.image.model);
        cfg.image.api_key_env         = get_or<std::string>(sec["api_key_env"],         cfg.image.api_key_env);
        cfg.image.generations_endpoint= get_or<std::string>(sec["generations_endpoint"],cfg.image.generations_endpoint);
        cfg.image.edits_endpoint      = get_or<std::string>(sec["edits_endpoint"],      cfg.image.edits_endpoint);
        cfg.image.default_size        = get_or<std::string>(sec["default_size"],        cfg.image.default_size);
        cfg.image.default_quality     = get_or<std::string>(sec["default_quality"],     cfg.image.default_quality);
        cfg.image.default_background  = get_or<std::string>(sec["default_background"],  cfg.image.default_background);
        cfg.image.default_format      = get_or<std::string>(sec["default_format"],      cfg.image.default_format);
        cfg.image.moderation          = get_or<std::string>(sec["moderation"],          cfg.image.moderation);
        cfg.image.max_n               = static_cast<int>(get_or<int64_t>(sec["max_n"],              cfg.image.max_n));
        cfg.image.timeout_s           = static_cast<int>(get_or<int64_t>(sec["timeout_s"],          cfg.image.timeout_s));
        cfg.image.max_retries         = static_cast<int>(get_or<int64_t>(sec["max_retries"],        cfg.image.max_retries));
        cfg.image.backoff_initial_ms  = static_cast<int>(get_or<int64_t>(sec["backoff_initial_ms"], cfg.image.backoff_initial_ms));
        cfg.image.job_poll_seconds    = static_cast<int>(get_or<int64_t>(sec["job_poll_seconds"],    cfg.image.job_poll_seconds));
        cfg.image.job_ttl_seconds     = static_cast<int>(get_or<int64_t>(sec["job_ttl_seconds"],     cfg.image.job_ttl_seconds));
        cfg.image.max_concurrent_jobs = static_cast<int>(get_or<int64_t>(sec["max_concurrent_jobs"], cfg.image.max_concurrent_jobs));
    }
    // The key is resolved regardless of whether [image] was present, so the
    // ambient OPENAI_API_KEY works with a bare config.
    if (!cfg.image.api_key_env.empty()) {
        cfg.image.api_key = env_or_empty(cfg.image.api_key_env.c_str());
    }

    // ----- [mcp] -----
    if (auto sec = tbl["mcp"]; sec.is_table()) {
        cfg.mcp.transport = get_or<std::string>(sec["transport"], cfg.mcp.transport);
        cfg.mcp.tcp_bind  = get_or<std::string>(sec["tcp_bind"],  cfg.mcp.tcp_bind);
        cfg.mcp.http_bind = get_or<std::string>(sec["http_bind"], cfg.mcp.http_bind);
        cfg.mcp.http_max_body_bytes  = static_cast<int>(get_or<int64_t>(sec["http_max_body_bytes"],  cfg.mcp.http_max_body_bytes));
        cfg.mcp.http_read_timeout_s  = static_cast<int>(get_or<int64_t>(sec["http_read_timeout_s"],  cfg.mcp.http_read_timeout_s));
        cfg.mcp.http_write_timeout_s = static_cast<int>(get_or<int64_t>(sec["http_write_timeout_s"], cfg.mcp.http_write_timeout_s));
    }

    // ----- [auth] -----
    if (auto sec = tbl["auth"]; sec.is_table()) {
        cfg.auth.enabled               = get_or<bool>(sec["enabled"], cfg.auth.enabled);
        cfg.auth.resource_metadata_url = get_or<std::string>(sec["resource_metadata_url"], "");
        cfg.auth.jwt_issuer            = get_or<std::string>(sec["jwt_issuer"],    "");
        cfg.auth.jwt_audience          = get_or<std::string>(sec["jwt_audience"],  "");
        cfg.auth.jwt_jwks_url          = get_or<std::string>(sec["jwt_jwks_url"],  "");
        cfg.auth.jwt_principal_claim   = get_or<std::string>(sec["jwt_principal_claim"], cfg.auth.jwt_principal_claim);

        if (auto arr = sec["principals"].as_array()) {
            for (const auto& elem : *arr) {
                const auto* pt = elem.as_table();
                if (!pt) continue;
                AuthPrincipalConfig p;
                p.name            = (*pt)["name"].value_or<std::string>("");
                p.home_realm      = (*pt)["home_realm"].value_or<std::string>("");
                p.max_sensitivity = (*pt)["max_sensitivity"].value_or<std::string>("");
                if (auto ra = (*pt)["read_realms"].as_array())
                    for (const auto& v : *ra)
                        if (auto s = v.value<std::string>()) p.read_realms.push_back(*s);
                if (auto wa = (*pt)["write_realms"].as_array())
                    for (const auto& v : *wa)
                        if (auto s = v.value<std::string>()) p.write_realms.push_back(*s);
                if (p.name.empty())
                    throw std::runtime_error("config: [[auth.principals]] entry missing name");
                if (p.home_realm.empty())
                    throw std::runtime_error("config: auth principal '" + p.name + "' missing home_realm");
                cfg.auth.principals.push_back(std::move(p));
            }
        }
        // jwt_subject_map = [["sub-uuid","name"], ...]
        if (auto arr = sec["jwt_subject_map"].as_array()) {
            for (const auto& elem : *arr) {
                const auto* pair = elem.as_array();
                if (!pair || pair->size() != 2) continue;
                auto k = (*pair)[0].value<std::string>();
                auto v = (*pair)[1].value<std::string>();
                if (k && v) cfg.auth.jwt_subject_map.emplace_back(*k, *v);
            }
        }

        // ----- [auth.oauth] — embedded authorization server -----
        if (auto osec = sec["oauth"]; osec.is_table()) {
            auto& oa = cfg.auth.oauth;
            oa.enabled          = get_or<bool>(osec["enabled"], oa.enabled);
            oa.issuer           = get_or<std::string>(osec["issuer"],           "");
            oa.resource         = get_or<std::string>(osec["resource"],         "");
            oa.signing_key_path = get_or<std::string>(osec["signing_key_path"], "");
            if (auto arr = osec["previous_key_paths"].as_array()) {
                for (const auto& v : *arr)
                    if (auto s = v.value<std::string>()) oa.previous_key_paths.push_back(*s);
            }
            if (auto arr = osec["redirect_hosts"].as_array()) {
                oa.redirect_hosts.clear();  // explicit list replaces the default
                for (const auto& v : *arr)
                    if (auto s = v.value<std::string>()) oa.redirect_hosts.push_back(*s);
            }
            oa.access_token_ttl_s  = static_cast<int>(get_or<int64_t>(osec["access_token_ttl_s"],  oa.access_token_ttl_s));
            oa.auth_code_ttl_s     = static_cast<int>(get_or<int64_t>(osec["auth_code_ttl_s"],     oa.auth_code_ttl_s));
            oa.refresh_token_ttl_s = static_cast<int>(get_or<int64_t>(osec["refresh_token_ttl_s"], oa.refresh_token_ttl_s));
            oa.max_clients         = static_cast<int>(get_or<int64_t>(osec["max_clients"],         oa.max_clients));

            if (oa.enabled) {
                if (oa.issuer.empty())
                    throw std::runtime_error("config: auth.oauth.issuer required when oauth is enabled");
                if (oa.resource.empty())
                    throw std::runtime_error("config: auth.oauth.resource required when oauth is enabled");
                if (oa.signing_key_path.empty())
                    throw std::runtime_error("config: auth.oauth.signing_key_path required when oauth is enabled");
                if (oa.issuer.back() == '/')
                    throw std::runtime_error("config: auth.oauth.issuer must not end with '/'");
            }
        }

        // Derive the verify side from the mint side so they cannot drift.
        if (cfg.auth.oauth.enabled) {
            if (cfg.auth.jwt_issuer.empty())   cfg.auth.jwt_issuer   = cfg.auth.oauth.issuer;
            if (cfg.auth.jwt_audience.empty()) cfg.auth.jwt_audience = cfg.auth.oauth.resource;
            if (cfg.auth.resource_metadata_url.empty()) {
                cfg.auth.resource_metadata_url =
                    cfg.auth.oauth.issuer + "/.well-known/oauth-protected-resource/mcp";
            }
        }

        // A JWT verifier needs an audience to check against — otherwise a token
        // minted for a different resource by a shared issuer would be accepted.
        // Fail closed at load rather than silently skipping the audience check.
        if (!cfg.auth.jwt_issuer.empty() && cfg.auth.jwt_audience.empty()) {
            throw std::runtime_error(
                "config: auth.jwt_audience is required when a JWT issuer is set "
                "(prevents cross-audience token replay)");
        }
    }

    // ----- [logging] -----
    if (auto sec = tbl["logging"]; sec.is_table()) {
        cfg.logging.level        = get_or<std::string>(sec["level"],                cfg.logging.level);
        cfg.logging.path         = get_or<std::string>(sec["path"],                 "");
        cfg.logging.rotate_mb    = static_cast<int>(get_or<int64_t>(sec["rotate_mb"],    cfg.logging.rotate_mb));
        cfg.logging.retain_files = static_cast<int>(get_or<int64_t>(sec["retain_files"], cfg.logging.retain_files));
    }

    return cfg;
}

std::filesystem::path default_config_path() {
    if (auto p = env_or_empty("GPTIMAGE_CONFIG"); !p.empty()) {
        return std::filesystem::path(std::move(p));
    }
    for (const auto& c : candidate_config_paths()) {
        if (std::filesystem::exists(c)) return c;
    }
    return std::filesystem::path("config") / "gptimage.toml";
}

}  // namespace gptimage
