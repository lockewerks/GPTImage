#include <gptimage/auth.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <stdexcept>

namespace gptimage {

namespace {

// base64url (RFC 4648 §5), no padding.
std::string base64url(const unsigned char* data, size_t len) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        const uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(tbl[(n >> 6) & 63]);
        out.push_back(tbl[n & 63]);
    }
    if (len - i == 1) {
        const uint32_t n = uint32_t(data[i]) << 16;
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
    } else if (len - i == 2) {
        const uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(tbl[(n >> 6) & 63]);
    }
    return out;
}

// Convert config/JSON realm lists into (all, explicit-list): a list containing
// "*" collapses to the wildcard with an empty explicit list.
void apply_realm_list(const std::vector<std::string>& in, bool& all,
                      std::vector<std::string>& out) {
    all = false;
    out.clear();
    for (const auto& r : in) {
        if (r == "*") { all = true; out.clear(); return; }
        out.push_back(r);
    }
}

}  // namespace

std::string generate_token() {
    std::array<unsigned char, 32> buf{};
    if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) {
        throw std::runtime_error("generate_token: RAND_bytes failed");
    }
    return "gpt_" + base64url(buf.data(), buf.size());
}

std::string sha256_hex(std::string_view data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_Digest(data.data(), data.size(), md, &md_len, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("sha256_hex: EVP_Digest failed");
    }
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(md_len * 2);
    for (unsigned int i = 0; i < md_len; ++i) {
        out.push_back(hex[md[i] >> 4]);
        out.push_back(hex[md[i] & 0x0f]);
    }
    return out;
}

bool constant_time_equals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

bool parse_bearer(const std::string& header, std::string& token_out) {
    token_out.clear();
    // Skip leading whitespace.
    size_t i = 0;
    while (i < header.size() && std::isspace(static_cast<unsigned char>(header[i]))) ++i;
    // Case-insensitive "bearer" scheme.
    static const std::string scheme = "bearer";
    if (header.size() - i < scheme.size()) return false;
    for (size_t j = 0; j < scheme.size(); ++j) {
        if (std::tolower(static_cast<unsigned char>(header[i + j])) != scheme[j]) return false;
    }
    i += scheme.size();
    // Require at least one space between scheme and token.
    if (i >= header.size() || !std::isspace(static_cast<unsigned char>(header[i]))) return false;
    while (i < header.size() && std::isspace(static_cast<unsigned char>(header[i]))) ++i;
    // Token is the rest, right-trimmed.
    size_t end = header.size();
    while (end > i && std::isspace(static_cast<unsigned char>(header[end - 1]))) --end;
    if (end <= i) return false;
    token_out = header.substr(i, end - i);
    return true;
}

bool grant_from_json(const nlohmann::json& grants,
                     const std::string& principal,
                     RealmGrant& out,
                     std::string& err) {
    err.clear();
    if (!grants.is_object()) {
        err = "token grants is not an object";
        return false;
    }
    const std::string home = grants.value("home", std::string());
    if (home.empty()) {
        err = "token grants missing 'home' realm";
        return false;
    }

    auto read_str_array = [&](const char* key, std::vector<std::string>& dst) -> bool {
        if (!grants.contains(key)) return true;  // optional
        if (!grants[key].is_array()) { err = std::string("token grants '") + key + "' not an array"; return false; }
        for (const auto& v : grants[key]) {
            if (!v.is_string()) { err = std::string("token grants '") + key + "' has non-string"; return false; }
            dst.push_back(v.get<std::string>());
        }
        return true;
    };

    std::vector<std::string> read_list, write_list;
    if (!read_str_array("read", read_list))   return false;
    if (!read_str_array("write", write_list)) return false;

    out = RealmGrant{};
    out.principal       = principal;
    out.home_realm      = home;
    out.max_sensitivity = grants.value("max_sensitivity", std::string());
    apply_realm_list(read_list,  out.read_all,  out.read_realms);
    apply_realm_list(write_list, out.write_all, out.write_realms);
    return true;
}

std::optional<RealmGrant> grant_from_config(const AuthConfig& cfg,
                                            const std::string& principal) {
    for (const auto& p : cfg.principals) {
        if (p.name != principal) continue;
        RealmGrant g;
        g.principal       = p.name;
        g.home_realm      = p.home_realm;
        g.max_sensitivity = p.max_sensitivity;
        apply_realm_list(p.read_realms,  g.read_all,  g.read_realms);
        apply_realm_list(p.write_realms, g.write_all, g.write_realms);
        return g;
    }
    return std::nullopt;
}

std::optional<std::string> resolve_jwt_principal(const AuthConfig& cfg,
                                                 const nlohmann::json& claims) {
    const std::string& claim_name =
        cfg.jwt_principal_claim.empty() ? std::string("sub") : cfg.jwt_principal_claim;

    const auto it = claims.find(claim_name);
    if (it == claims.end() || !it->is_string()) return std::nullopt;
    std::string value = it->get<std::string>();
    if (value.empty()) return std::nullopt;

    for (const auto& [from, to] : cfg.jwt_subject_map) {
        if (from == value) return to;
    }
    return value;
}

}  // namespace gptimage
