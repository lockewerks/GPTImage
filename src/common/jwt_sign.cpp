#include <gptimage/jwt_sign.hpp>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace gptimage {

using nlohmann::json;

namespace {

// base64url (RFC 4648 §5), no padding. Deliberately local — auth.cpp,
// google_oauth.cpp, and jwt_verify.cpp each carry their own copy in an
// anonymous namespace; consolidating them is a separate cleanup.
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

std::string base64url(const std::string& s) {
    return base64url(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

std::string openssl_last_error() {
    unsigned long e = ERR_get_error();
    if (!e) return "(no openssl error)";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(buf);
}

struct BioDeleter { void operator()(BIO* b) const { BIO_free(b); } };
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

struct BnDeleter { void operator()(BIGNUM* b) const { BN_free(b); } };
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;

struct EvpMdCtxDeleter { void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); } };
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

// Big-endian bytes of a BIGNUM, base64url-encoded (JWK integer encoding).
std::string bn_to_b64url(const BIGNUM* bn) {
    const int n = BN_num_bytes(bn);
    std::string bytes(static_cast<size_t>(n), '\0');
    BN_bn2bin(bn, reinterpret_cast<unsigned char*>(bytes.data()));
    return base64url(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
}

std::string read_entire(const std::filesystem::path& p) {
    std::ifstream is(p, std::ios::binary);
    if (!is) throw std::runtime_error("jwt_sign: cannot read: " + p.string());
    std::ostringstream os;
    os << is.rdbuf();
    return os.str();
}

}  // namespace

struct SigningKey::Impl {
    EVP_PKEY* pkey = nullptr;
    ~Impl() { if (pkey) EVP_PKEY_free(pkey); }
};

SigningKey::SigningKey(SigningKey&&) noexcept = default;
SigningKey& SigningKey::operator=(SigningKey&&) noexcept = default;
SigningKey::~SigningKey() = default;

SigningKey SigningKey::load_pem(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) throw std::runtime_error("jwt_sign: BIO_new_mem_buf failed: " + openssl_last_error());

    EVP_PKEY* raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) {
        throw std::runtime_error("jwt_sign: PEM_read_bio_PrivateKey failed (not a PEM private key?): " +
                                 openssl_last_error());
    }

    SigningKey key;
    key.impl_ = std::make_unique<Impl>();
    key.impl_->pkey = raw;

    if (EVP_PKEY_base_id(raw) != EVP_PKEY_RSA) {
        throw std::runtime_error("jwt_sign: key is not RSA — the mint path is RS256-only");
    }

    // Public JWK from the RSA n/e params.
    BIGNUM* n_raw = nullptr;
    BIGNUM* e_raw = nullptr;
    if (EVP_PKEY_get_bn_param(raw, OSSL_PKEY_PARAM_RSA_N, &n_raw) != 1 ||
        EVP_PKEY_get_bn_param(raw, OSSL_PKEY_PARAM_RSA_E, &e_raw) != 1) {
        BN_free(n_raw);
        throw std::runtime_error("jwt_sign: cannot extract RSA n/e: " + openssl_last_error());
    }
    BnPtr n_bn(n_raw), e_bn(e_raw);
    const std::string n_b64 = bn_to_b64url(n_bn.get());
    const std::string e_b64 = bn_to_b64url(e_bn.get());

    // RFC 7638 thumbprint: SHA-256 over the canonical JSON of the REQUIRED
    // public members only, keys in lexicographic order: {"e":..,"kty":..,"n":..}.
    // nlohmann::json objects serialize alphabetically, which is exactly that
    // order for these three keys.
    const std::string canonical =
        json{{"e", e_b64}, {"kty", "RSA"}, {"n", n_b64}}.dump();
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(canonical.data()), canonical.size(), digest);
    key.kid_ = base64url(digest, sizeof(digest));

    key.public_jwk_ = json{
        {"kty", "RSA"},
        {"use", "sig"},
        {"alg", "RS256"},
        {"kid", key.kid_},
        {"n", n_b64},
        {"e", e_b64},
    };
    return key;
}

SigningKey SigningKey::load_pem_file(const std::filesystem::path& path) {
    return load_pem(read_entire(path));
}

std::string SigningKey::sign_rs256(const std::string& signing_input) const {
    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) throw std::runtime_error("jwt_sign: EVP_MD_CTX_new failed");

    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, impl_->pkey) != 1) {
        throw std::runtime_error("jwt_sign: EVP_DigestSignInit failed: " + openssl_last_error());
    }
    size_t sig_len = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &sig_len,
                       reinterpret_cast<const unsigned char*>(signing_input.data()),
                       signing_input.size()) != 1) {
        throw std::runtime_error("jwt_sign: EVP_DigestSign (size) failed: " + openssl_last_error());
    }
    std::string sig(sig_len, '\0');
    if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(sig.data()), &sig_len,
                       reinterpret_cast<const unsigned char*>(signing_input.data()),
                       signing_input.size()) != 1) {
        throw std::runtime_error("jwt_sign: EVP_DigestSign failed: " + openssl_last_error());
    }
    sig.resize(sig_len);
    return sig;
}

std::string generate_rsa_key_pem(int bits) {
    EVP_PKEY* raw = EVP_RSA_gen(static_cast<unsigned int>(bits));
    if (!raw) throw std::runtime_error("jwt_sign: EVP_RSA_gen failed: " + openssl_last_error());
    struct PkeyGuard { EVP_PKEY* p; ~PkeyGuard() { EVP_PKEY_free(p); } } guard{raw};

    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio) throw std::runtime_error("jwt_sign: BIO_new failed");
    if (PEM_write_bio_PKCS8PrivateKey(bio.get(), raw, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        throw std::runtime_error("jwt_sign: PEM_write_bio_PKCS8PrivateKey failed: " +
                                 openssl_last_error());
    }
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<size_t>(len));
}

std::string sign_jwt_rs256(const SigningKey& key, const json& claims) {
    const json header = {
        {"alg", "RS256"},
        {"typ", "JWT"},
        {"kid", key.kid()},
    };
    const std::string signing_input =
        base64url(header.dump()) + "." + base64url(claims.dump());
    const std::string sig = key.sign_rs256(signing_input);
    return signing_input + "." +
           base64url(reinterpret_cast<const unsigned char*>(sig.data()), sig.size());
}

json jwks_json(const std::vector<SigningKey>& keys) {
    json arr = json::array();
    for (const auto& k : keys) arr.push_back(k.public_jwk());
    return json{{"keys", std::move(arr)}};
}

}  // namespace gptimage
