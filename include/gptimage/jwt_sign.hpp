#pragma once

#include <nlohmann/json.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

// RS256 JWT minting for the embedded OAuth authorization server. The verify
// side lives in jwt_verify.hpp; this is the mint side. Same algorithm floor:
// RS256 only, on purpose — one signing scheme, no negotiation surface.
//
// Key identity follows RFC 7638: kid = base64url(SHA-256(canonical public
// JWK)), so a key file IS its kid and rotation never needs a name registry.

namespace gptimage {

// An RSA private key loaded from PEM plus its derived public JWK and kid.
// Move-only; the EVP_PKEY is owned for the SigningKey's lifetime.
class SigningKey {
public:
    // Load a PEM (PKCS#8 or PKCS#1) private key from disk. Throws
    // std::runtime_error with an OpenSSL reason on any failure, including a
    // non-RSA key — the mint path is RS256-only.
    static SigningKey load_pem_file(const std::filesystem::path& path);

    // Same, from an in-memory PEM string (tests, keygen round-trip).
    static SigningKey load_pem(const std::string& pem);

    SigningKey(SigningKey&&) noexcept;
    SigningKey& operator=(SigningKey&&) noexcept;
    SigningKey(const SigningKey&) = delete;
    SigningKey& operator=(const SigningKey&) = delete;
    ~SigningKey();

    // RFC 7638 thumbprint of the public key (base64url, no padding).
    const std::string& kid() const { return kid_; }

    // Public JWK: {kty,n,e,alg:"RS256",use:"sig",kid}. Safe to publish.
    const nlohmann::json& public_jwk() const { return public_jwk_; }

    // Raw RSA-SHA256 signature bytes over `signing_input` (caller encodes).
    std::string sign_rs256(const std::string& signing_input) const;

private:
    SigningKey() = default;

    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::string           kid_;
    nlohmann::json        public_jwk_;
};

// Generate a fresh RSA private key and return it PEM-encoded (PKCS#8).
// Used by `gptimage_cli oauth keygen` and by tests. Throws on failure.
std::string generate_rsa_key_pem(int bits = 2048);

// Mint a compact RS256 JWT: header {"alg":"RS256","typ":"JWT","kid":...} +
// `claims` payload, signed by `key`. The caller owns claim correctness
// (iss/aud/sub/exp/iat/jti) — this function only encodes and signs.
std::string sign_jwt_rs256(const SigningKey& key, const nlohmann::json& claims);

// JWKS document for the given keys: {"keys":[public_jwk...]}. Publish the
// active key plus any previous keys whose tokens may still be live.
nlohmann::json jwks_json(const std::vector<SigningKey>& keys);

}  // namespace gptimage
