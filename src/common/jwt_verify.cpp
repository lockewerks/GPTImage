#include <gptimage/jwt_verify.hpp>

#include <cpr/cpr.h>
#include <spdlog/spdlog.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include <cstdint>
#include <ctime>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace gptimage {

using nlohmann::json;

namespace {

// --- base64url decode (no padding) ------------------------------------------
int b64url_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

bool base64url_decode(const std::string& in, std::vector<unsigned char>& out) {
    out.clear();
    out.reserve(in.size() * 3 / 4 + 3);
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=') break;
        const int v = b64url_val(c);
        if (v < 0) return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<unsigned char>((acc >> bits) & 0xFF));
        }
    }
    return true;
}

std::string b64url_to_string(const std::string& in) {
    std::vector<unsigned char> raw;
    if (!base64url_decode(in, raw)) return {};
    return std::string(reinterpret_cast<const char*>(raw.data()), raw.size());
}

using EvpPkeyPtr = std::shared_ptr<EVP_PKEY>;

// Build an RSA public EVP_PKEY from JWK n/e (both base64url big-endian).
EvpPkeyPtr rsa_key_from_jwk(const std::string& n_b64, const std::string& e_b64) {
    std::vector<unsigned char> n_bytes, e_bytes;
    if (!base64url_decode(n_b64, n_bytes) || !base64url_decode(e_b64, e_bytes)) return nullptr;

    BIGNUM* n = BN_bin2bn(n_bytes.data(), static_cast<int>(n_bytes.size()), nullptr);
    BIGNUM* e = BN_bin2bn(e_bytes.data(), static_cast<int>(e_bytes.size()), nullptr);
    if (!n || !e) { BN_free(n); BN_free(e); return nullptr; }

    EvpPkeyPtr result;
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM* params = nullptr;
    if (bld &&
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) &&
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
        params = OSSL_PARAM_BLD_to_param(bld);
    }
    if (params) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        if (ctx && EVP_PKEY_fromdata_init(ctx) > 0) {
            EVP_PKEY* pkey = nullptr;
            if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0 && pkey) {
                result = EvpPkeyPtr(pkey, EVP_PKEY_free);
            }
        }
        if (ctx) EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
    }
    if (bld) OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    return result;
}

// Process-wide JWKS key cache keyed by (jwks_url, kid). Guarded by a mutex; in
// practice JWKS fetch happens inside the server's request critical section, but
// the lock keeps this correct if that ever changes.
// A cached JWKS is refreshed at least this often even for a known kid, so a
// key an external issuer rotates out or revokes stops being trusted within the
// window (rather than until process restart). Moot for the embedded AS (local
// fetcher serving a static doc — the refresh is a cheap no-op) but load-bearing
// for the external-IdP path.
constexpr std::time_t kKeyMaxAgeS = 3600;

struct JwksCache {
    std::mutex mtx;
    std::map<std::string, EvpPkeyPtr> keys;   // key = jwks_url + "\n" + kid
    std::map<std::string, std::time_t> fetched_at;  // key = jwks_url

    EvpPkeyPtr get(const std::string& url, const std::string& kid) {
        std::lock_guard<std::mutex> lk(mtx);
        // Stale beyond the max age ⇒ miss, forcing verify() to refetch.
        auto fa = fetched_at.find(url);
        if (fa != fetched_at.end() && std::time(nullptr) - fa->second > kKeyMaxAgeS) {
            return nullptr;
        }
        auto it = keys.find(url + "\n" + kid);
        return it == keys.end() ? nullptr : it->second;
    }
    bool may_refetch(const std::string& url, int min_interval_s) {
        std::lock_guard<std::mutex> lk(mtx);
        const std::time_t now = std::time(nullptr);
        auto it = fetched_at.find(url);
        if (it != fetched_at.end() && now - it->second < min_interval_s) return false;
        fetched_at[url] = now;
        return true;
    }
    void store(const std::string& url, const std::map<std::string, EvpPkeyPtr>& kid_keys) {
        std::lock_guard<std::mutex> lk(mtx);
        for (const auto& [kid, key] : kid_keys) keys[url + "\n" + kid] = key;
    }
};

JwksCache& jwks_cache() {
    static JwksCache c;
    return c;
}

// Parse a JWKS document into kid->EVP_PKEY for RSA signing keys.
std::map<std::string, EvpPkeyPtr> parse_jwks(const std::string& body) {
    std::map<std::string, EvpPkeyPtr> out;
    json doc = json::parse(body, nullptr, false);
    if (doc.is_discarded() || !doc.contains("keys") || !doc["keys"].is_array()) return out;
    for (const auto& k : doc["keys"]) {
        if (k.value("kty", "") != "RSA") continue;
        if (k.contains("use") && k["use"] != "sig") continue;
        const std::string kid = k.value("kid", "");
        const std::string n = k.value("n", "");
        const std::string e = k.value("e", "");
        if (kid.empty() || n.empty() || e.empty()) continue;
        if (auto key = rsa_key_from_jwk(n, e)) out[kid] = key;
    }
    return out;
}

}  // namespace

JwtVerifier::JwtVerifier(std::string issuer, std::string audience, std::string jwks_url,
                         Fetcher fetcher, int clock_skew_s)
    : issuer_(std::move(issuer)),
      audience_(std::move(audience)),
      jwks_url_(std::move(jwks_url)),
      fetcher_(std::move(fetcher)),
      clock_skew_s_(clock_skew_s) {
    if (!fetcher_) {
        fetcher_ = [](const std::string& url) -> std::string {
            auto r = cpr::Get(cpr::Url{url}, cpr::Timeout{5000});
            if (r.status_code != 200) return {};
            return r.text;
        };
    }
}

std::optional<VerifiedJwt> JwtVerifier::verify(const std::string& compact, std::string& err) {
    err.clear();

    // Split into header.payload.signature.
    const auto d1 = compact.find('.');
    const auto d2 = compact.find('.', d1 == std::string::npos ? 0 : d1 + 1);
    if (d1 == std::string::npos || d2 == std::string::npos || d2 == d1 + 1) {
        err = "malformed JWT (need header.payload.signature)";
        return std::nullopt;
    }
    const std::string header_b64 = compact.substr(0, d1);
    const std::string payload_b64 = compact.substr(d1 + 1, d2 - d1 - 1);
    const std::string sig_b64 = compact.substr(d2 + 1);
    const std::string signing_input = compact.substr(0, d2);

    json header = json::parse(b64url_to_string(header_b64), nullptr, false);
    if (header.is_discarded() || !header.is_object()) { err = "bad JWT header"; return std::nullopt; }
    // Guard against a non-string alg/kid: nlohmann value<T>() throws type_error
    // on {"alg":123}, and verify() has no try/catch, so an unguarded read would
    // unwind to a 500. Treat any non-string as a clean rejection.
    if (!header.contains("alg") || !header["alg"].is_string() ||
        header["alg"].get<std::string>() != "RS256") {
        err = "unsupported or missing alg (RS256 only)";
        return std::nullopt;
    }
    if (!header.contains("kid") || !header["kid"].is_string() ||
        header["kid"].get<std::string>().empty()) {
        err = "JWT header missing kid";
        return std::nullopt;
    }
    const std::string kid = header["kid"].get<std::string>();

    // Resolve the signing key (cache, then one rate-limited refetch on miss).
    EvpPkeyPtr key = jwks_cache().get(jwks_url_, kid);
    if (!key && jwks_cache().may_refetch(jwks_url_, /*min_interval_s=*/30)) {
        const std::string body = fetcher_(jwks_url_);
        if (!body.empty()) {
            jwks_cache().store(jwks_url_, parse_jwks(body));
            key = jwks_cache().get(jwks_url_, kid);
        }
    }
    if (!key) { err = "no JWKS key for kid " + kid; return std::nullopt; }

    // Verify the RS256 signature over signing_input.
    std::vector<unsigned char> sig;
    if (!base64url_decode(sig_b64, sig)) { err = "bad signature encoding"; return std::nullopt; }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool sig_ok = false;
    if (ctx &&
        EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key.get()) == 1) {
        const int rc = EVP_DigestVerify(
            ctx, sig.data(), sig.size(),
            reinterpret_cast<const unsigned char*>(signing_input.data()), signing_input.size());
        sig_ok = (rc == 1);
    }
    if (ctx) EVP_MD_CTX_free(ctx);
    if (!sig_ok) { err = "signature verification failed"; return std::nullopt; }

    // Claims.
    json claims = json::parse(b64url_to_string(payload_b64), nullptr, false);
    if (claims.is_discarded() || !claims.is_object()) { err = "bad JWT claims"; return std::nullopt; }

    const std::time_t now = std::time(nullptr);
    if (claims.contains("exp") && claims["exp"].is_number()) {
        if (now > claims["exp"].get<std::time_t>() + clock_skew_s_) { err = "token expired"; return std::nullopt; }
    } else { err = "missing exp"; return std::nullopt; }
    if (claims.contains("nbf") && claims["nbf"].is_number()) {
        if (now + clock_skew_s_ < claims["nbf"].get<std::time_t>()) { err = "token not yet valid"; return std::nullopt; }
    }
    // Issuer and audience are REQUIRED to be configured — an empty expected
    // issuer/audience is a misconfiguration, not "skip the check". Failing
    // closed here prevents an external IdP's token minted for a different
    // audience from being replayed against this resource. (The embedded AS
    // always supplies both via config derivation, so this never trips there.)
    if (issuer_.empty()) { err = "verifier misconfigured: no expected issuer"; return std::nullopt; }
    if (audience_.empty()) { err = "verifier misconfigured: no expected audience"; return std::nullopt; }
    if (claims.value("iss", "") != issuer_) { err = "issuer mismatch"; return std::nullopt; }
    {
        bool aud_ok = false;
        if (claims.contains("aud")) {
            if (claims["aud"].is_string()) aud_ok = claims["aud"] == audience_;
            else if (claims["aud"].is_array())
                for (const auto& a : claims["aud"]) if (a == audience_) { aud_ok = true; break; }
        }
        if (!aud_ok) { err = "audience mismatch"; return std::nullopt; }
    }

    VerifiedJwt vj;
    vj.subject = claims.value("sub", "");
    vj.claims = std::move(claims);
    return vj;
}

}  // namespace gptimage
