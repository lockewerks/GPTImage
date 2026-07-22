#include <gptimage/password_hash.hpp>

#include <gptimage/auth.hpp>  // constant_time_equals

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <array>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace gptimage {

namespace {

// Mint-time parameters. ln=17 ⇒ N=131072; memory ≈ 128*N*r = 128 MiB — meets
// the documented floor and stays under the 256 MiB verify cap. Older ln=15
// (32 MiB) rows still verify (their params travel in the PHC string), so this
// bump needs no migration; passwords re-hash to ln=17 on the next `passwd`.
constexpr uint64_t kLn      = 17;
constexpr uint32_t kR       = 8;
constexpr uint32_t kP       = 1;
constexpr size_t   kSaltLen = 16;
constexpr size_t   kHashLen = 32;

// Optional server-side pepper (GPTIMAGE_PASSWORD_PEPPER). When set, the
// password is HMAC-SHA256'd with it BEFORE scrypt, and the PHC records
// `pep=v1` so verify knows to apply it. A stolen credentials table alone is
// then uncrackable without the pepper (which lives in the app host's env, a
// separate host from the VPS Postgres). Backward compatible: rows without the
// marker verify with no pepper, and with the env unset behavior is unchanged.
constexpr const char* kPepperEnv     = "GPTIMAGE_PASSWORD_PEPPER";
constexpr const char* kPepperVersion = "v1";

// Verify-time parameter ceilings. The PHC string comes from our own DB, but a
// tampered row must not be able to turn one login attempt into a gigabyte
// derivation — cap at ln=17/r=32/p=16 and give OpenSSL a hard maxmem.
constexpr uint64_t kMaxLn     = 17;
constexpr uint32_t kMaxR      = 32;
constexpr uint32_t kMaxP      = 16;
constexpr uint64_t kMaxMemory = 256ull * 1024 * 1024;

// PHC "B64": standard base64 alphabet, no padding.
constexpr char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64_encode(const unsigned char* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        const uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
        out.push_back(kB64[(n >> 18) & 63]);
        out.push_back(kB64[(n >> 12) & 63]);
        out.push_back(kB64[(n >> 6) & 63]);
        out.push_back(kB64[n & 63]);
    }
    if (len - i == 1) {
        const uint32_t n = uint32_t(data[i]) << 16;
        out.push_back(kB64[(n >> 18) & 63]);
        out.push_back(kB64[(n >> 12) & 63]);
    } else if (len - i == 2) {
        const uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
        out.push_back(kB64[(n >> 18) & 63]);
        out.push_back(kB64[(n >> 12) & 63]);
        out.push_back(kB64[(n >> 6) & 63]);
    }
    return out;
}

bool b64_decode(std::string_view in, std::vector<unsigned char>& out) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.clear();
    if (in.size() % 4 == 1) return false;  // impossible length
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        const int v = val(c);
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

// The configured pepper, or empty if unset.
std::string env_pepper() {
#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable : 4996)
#endif
    const char* v = std::getenv(kPepperEnv);
#ifdef _MSC_VER
#  pragma warning(pop)
#endif
    return v ? std::string(v) : std::string();
}

// HMAC-SHA256(pepper, password) → raw MAC bytes; empty on failure. Applied
// before scrypt so the stored hash is a function of the pepper too.
std::string hmac_pepper(std::string_view pepper, std::string_view password) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    const unsigned char* out = HMAC(
        EVP_sha256(),
        pepper.data(), static_cast<int>(pepper.size()),
        reinterpret_cast<const unsigned char*>(password.data()), password.size(),
        mac, &len);
    if (!out || len == 0) return {};
    return std::string(reinterpret_cast<const char*>(mac), len);
}

// Run scrypt with the given parameters. Returns false on KDF failure.
bool scrypt_derive(std::string_view password,
                   const std::vector<unsigned char>& salt,
                   uint64_t n, uint32_t r, uint32_t p,
                   std::vector<unsigned char>& out) {
    struct KdfDeleter { void operator()(EVP_KDF* k) const { EVP_KDF_free(k); } };
    struct CtxDeleter { void operator()(EVP_KDF_CTX* c) const { EVP_KDF_CTX_free(c); } };

    std::unique_ptr<EVP_KDF, KdfDeleter> kdf(EVP_KDF_fetch(nullptr, "SCRYPT", nullptr));
    if (!kdf) return false;
    std::unique_ptr<EVP_KDF_CTX, CtxDeleter> ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx) return false;

    uint64_t maxmem = kMaxMemory;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD,
            const_cast<char*>(password.data()), password.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            const_cast<unsigned char*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &p),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem),
        OSSL_PARAM_construct_end(),
    };

    out.assign(kHashLen, 0);
    return EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) == 1;
}

// Parse "ln=17,r=8,p=1" with an OPTIONAL trailing ",pep=<version>". `pep` is
// set to the pepper version when present, empty otherwise.
bool parse_params(std::string_view s, uint64_t& ln, uint32_t& r, uint32_t& p,
                  std::string& pep) {
    pep.clear();
    auto take_uint = [](std::string_view& sv, std::string_view key, auto& dst) -> bool {
        if (sv.substr(0, key.size()) != key) return false;
        sv.remove_prefix(key.size());
        const char* begin = sv.data();
        const char* end = sv.data() + sv.size();
        uint64_t v = 0;
        auto [ptr, ec] = std::from_chars(begin, end, v);
        if (ec != std::errc() || ptr == begin) return false;
        sv.remove_prefix(static_cast<size_t>(ptr - begin));
        dst = static_cast<std::remove_reference_t<decltype(dst)>>(v);
        return true;
    };
    uint64_t r64 = 0, p64 = 0;
    if (!take_uint(s, "ln=", ln)) return false;
    if (s.empty() || s.front() != ',') return false;
    s.remove_prefix(1);
    if (!take_uint(s, "r=", r64)) return false;
    if (s.empty() || s.front() != ',') return false;
    s.remove_prefix(1);
    if (!take_uint(s, "p=", p64)) return false;
    // Optional pepper marker.
    if (!s.empty()) {
        constexpr std::string_view kPep = ",pep=";
        if (s.substr(0, kPep.size()) != kPep) return false;
        s.remove_prefix(kPep.size());
        if (s.empty()) return false;
        pep = std::string(s);
        s = {};
    }
    if (!s.empty()) return false;
    r = static_cast<uint32_t>(r64);
    p = static_cast<uint32_t>(p64);
    return true;
}

}  // namespace

std::string hash_password(std::string_view password) {
    std::array<unsigned char, kSaltLen> salt{};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        throw std::runtime_error("password_hash: RAND_bytes failed");
    }
    std::vector<unsigned char> salt_v(salt.begin(), salt.end());

    // Pepper (if configured) is HMAC'd in before scrypt; the KDF input is the
    // MAC bytes rather than the raw password.
    const std::string pepper = env_pepper();
    std::string peppered;
    std::string_view kdf_in = password;
    if (!pepper.empty()) {
        peppered = hmac_pepper(pepper, password);
        if (peppered.empty()) throw std::runtime_error("password_hash: pepper HMAC failed");
        kdf_in = peppered;
    }

    std::vector<unsigned char> dk;
    const bool ok = scrypt_derive(kdf_in, salt_v, uint64_t{1} << kLn, kR, kP, dk);
    if (!peppered.empty()) OPENSSL_cleanse(peppered.data(), peppered.size());
    if (!ok) throw std::runtime_error("password_hash: scrypt derivation failed");

    std::string params = "ln=" + std::to_string(kLn) +
                         ",r=" + std::to_string(kR) +
                         ",p=" + std::to_string(kP);
    if (!pepper.empty()) params += ",pep=" + std::string(kPepperVersion);
    return "$scrypt$" + params +
           "$" + b64_encode(salt_v.data(), salt_v.size()) +
           "$" + b64_encode(dk.data(), dk.size());
}

bool verify_password(std::string_view password, std::string_view phc) {
    // $scrypt$<params>$<salt>$<hash> — leading '$' then exactly four fields.
    if (phc.empty() || phc.front() != '$') return false;
    phc.remove_prefix(1);

    auto next_field = [&phc](std::string_view& out) -> bool {
        const size_t pos = phc.find('$');
        if (pos == std::string_view::npos) return false;
        out = phc.substr(0, pos);
        phc.remove_prefix(pos + 1);
        return true;
    };
    std::string_view id, params_s, salt_s;
    if (!next_field(id) || id != "scrypt") return false;
    if (!next_field(params_s)) return false;
    if (!next_field(salt_s)) return false;
    const std::string_view hash_s = phc;  // remainder
    if (hash_s.empty()) return false;

    uint64_t ln = 0;
    uint32_t r = 0, p = 0;
    std::string pep;
    if (!parse_params(params_s, ln, r, p, pep)) return false;
    if (ln < 10 || ln > kMaxLn || r < 1 || r > kMaxR || p < 1 || p > kMaxP) return false;

    std::vector<unsigned char> salt, expected;
    if (!b64_decode(salt_s, salt) || salt.size() < 8) return false;
    if (!b64_decode(hash_s, expected) || expected.size() != kHashLen) return false;

    // If the row was peppered, apply the same pepper. Fail closed if the marker
    // is present but the pepper is unavailable or an unknown version.
    std::string peppered;
    std::string_view kdf_in = password;
    if (!pep.empty()) {
        if (pep != kPepperVersion) return false;
        const std::string pepper = env_pepper();
        if (pepper.empty()) return false;
        peppered = hmac_pepper(pepper, password);
        if (peppered.empty()) return false;
        kdf_in = peppered;
    }

    std::vector<unsigned char> dk;
    const bool derived = scrypt_derive(kdf_in, salt, uint64_t{1} << ln, r, p, dk);
    if (!peppered.empty()) OPENSSL_cleanse(peppered.data(), peppered.size());
    if (!derived) return false;

    return constant_time_equals(
        std::string_view(reinterpret_cast<const char*>(dk.data()), dk.size()),
        std::string_view(reinterpret_cast<const char*>(expected.data()), expected.size()));
}

}  // namespace gptimage
