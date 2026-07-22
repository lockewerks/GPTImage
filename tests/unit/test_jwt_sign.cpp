#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <gptimage/jwt_sign.hpp>
#include <gptimage/jwt_verify.hpp>

#include <nlohmann/json.hpp>

#include <ctime>
#include <string>

using nlohmann::json;

namespace {

// One process-wide key: RSA keygen dominates test runtime, and every case
// here only needs *a* key, not a fresh one.
const std::string& test_pem() {
    static const std::string pem = gptimage::generate_rsa_key_pem(2048);
    return pem;
}

const gptimage::SigningKey& test_key() {
    static gptimage::SigningKey key = gptimage::SigningKey::load_pem(test_pem());
    return key;
}

// A JwtVerifier whose "fetch" serves our own JWKS — the exact shape the MCP
// server will use in production (local fetcher, no HTTP).
gptimage::JwtVerifier make_verifier(const std::string& issuer,
                                     const std::string& audience) {
    const std::string jwks = gptimage::jwks_json({}).dump();  // placeholder, see fetcher
    (void)jwks;
    auto fetcher = [](const std::string&) -> std::string {
        std::vector<gptimage::SigningKey> keys;
        keys.push_back(gptimage::SigningKey::load_pem(test_pem()));
        return gptimage::jwks_json(keys).dump();
    };
    return gptimage::JwtVerifier(issuer, audience, "local:test", fetcher);
}

json base_claims() {
    const std::time_t now = std::time(nullptr);
    return json{
        {"iss", "https://gptimage.test"},
        {"aud", "https://gptimage.test/mcp"},
        {"sub", "archon"},
        {"iat", now},
        {"exp", now + 3600},
    };
}

// base64url (no padding) — enough to hand-craft adversarial JWT headers.
std::string b64url(const std::string& in) {
    static const char* t =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    size_t i = 0;
    for (; i + 3 <= in.size(); i += 3) {
        unsigned n = (unsigned char)in[i] << 16 | (unsigned char)in[i+1] << 8 | (unsigned char)in[i+2];
        out.push_back(t[(n>>18)&63]); out.push_back(t[(n>>12)&63]);
        out.push_back(t[(n>>6)&63]);  out.push_back(t[n&63]);
    }
    if (in.size() - i == 1) {
        unsigned n = (unsigned char)in[i] << 16;
        out.push_back(t[(n>>18)&63]); out.push_back(t[(n>>12)&63]);
    } else if (in.size() - i == 2) {
        unsigned n = (unsigned char)in[i] << 16 | (unsigned char)in[i+1] << 8;
        out.push_back(t[(n>>18)&63]); out.push_back(t[(n>>12)&63]); out.push_back(t[(n>>6)&63]);
    }
    return out;
}

// A compact JWT with a caller-chosen header — the signature is irrelevant to
// these tests because the verifier must reject on `alg` BEFORE touching it.
std::string craft(const json& header, const json& payload, const std::string& sig = "AAAA") {
    return b64url(header.dump()) + "." + b64url(payload.dump()) + "." + sig;
}

}  // namespace

TEST_CASE("kid is a base64url RFC 7638 thumbprint") {
    const auto& key = test_key();
    CHECK(key.kid().size() == 43);  // 32 bytes -> 43 base64url chars, no padding
    CHECK(key.kid().find('=') == std::string::npos);
    CHECK(key.kid().find('+') == std::string::npos);
    CHECK(key.kid().find('/') == std::string::npos);

    // Deterministic: loading the same PEM twice yields the same kid.
    const auto again = gptimage::SigningKey::load_pem(test_pem());
    CHECK(again.kid() == key.kid());
}

TEST_CASE("public JWK carries the advertised fields and no private material") {
    const json jwk = test_key().public_jwk();
    CHECK(jwk.at("kty") == "RSA");
    CHECK(jwk.at("alg") == "RS256");
    CHECK(jwk.at("use") == "sig");
    CHECK(jwk.at("kid") == test_key().kid());
    CHECK(jwk.contains("n"));
    CHECK(jwk.contains("e"));
    CHECK_FALSE(jwk.contains("d"));
    CHECK_FALSE(jwk.contains("p"));
    CHECK_FALSE(jwk.contains("q"));
}

TEST_CASE("mint -> verify round trip via JwtVerifier with a local fetcher") {
    auto verifier = make_verifier("https://gptimage.test", "https://gptimage.test/mcp");

    const std::string jwt = gptimage::sign_jwt_rs256(test_key(), base_claims());
    std::string err;
    auto v = verifier.verify(jwt, err);
    REQUIRE_MESSAGE(v.has_value(), err);
    CHECK(v->subject == "archon");
    CHECK(v->claims.at("aud") == "https://gptimage.test/mcp");
}

TEST_CASE("verifier rejects expired tokens") {
    auto verifier = make_verifier("https://gptimage.test", "https://gptimage.test/mcp");
    json claims = base_claims();
    claims["exp"] = std::time(nullptr) - 3600;
    const std::string jwt = gptimage::sign_jwt_rs256(test_key(), claims);
    std::string err;
    CHECK_FALSE(verifier.verify(jwt, err).has_value());
    CHECK(err == "token expired");
}

TEST_CASE("verifier rejects wrong audience and wrong issuer") {
    std::string err;
    {
        auto verifier = make_verifier("https://gptimage.test", "https://other.example/mcp");
        const std::string jwt = gptimage::sign_jwt_rs256(test_key(), base_claims());
        CHECK_FALSE(verifier.verify(jwt, err).has_value());
        CHECK(err == "audience mismatch");
    }
    {
        auto verifier = make_verifier("https://evil.example", "https://gptimage.test/mcp");
        const std::string jwt = gptimage::sign_jwt_rs256(test_key(), base_claims());
        CHECK_FALSE(verifier.verify(jwt, err).has_value());
        CHECK(err == "issuer mismatch");
    }
}

TEST_CASE("verifier rejects a tampered payload") {
    auto verifier = make_verifier("https://gptimage.test", "https://gptimage.test/mcp");
    std::string jwt = gptimage::sign_jwt_rs256(test_key(), base_claims());

    // Flip a character inside the payload segment (between the two dots).
    const auto d1 = jwt.find('.');
    const auto d2 = jwt.find('.', d1 + 1);
    REQUIRE(d2 != std::string::npos);
    const size_t mid = d1 + 1 + (d2 - d1 - 1) / 2;
    jwt[mid] = (jwt[mid] == 'A') ? 'B' : 'A';

    std::string err;
    CHECK_FALSE(verifier.verify(jwt, err).has_value());
}

TEST_CASE("verifier rejects a token signed by a different key (unknown kid)") {
    auto verifier = make_verifier("https://gptimage.test", "https://gptimage.test/mcp");

    const auto stranger = gptimage::SigningKey::load_pem(gptimage::generate_rsa_key_pem(2048));
    const std::string jwt = gptimage::sign_jwt_rs256(stranger, base_claims());

    std::string err;
    CHECK_FALSE(verifier.verify(jwt, err).has_value());
    CHECK(err.find("no JWKS key for kid") == 0);
}

TEST_CASE("jwks_json publishes every key") {
    std::vector<gptimage::SigningKey> keys;
    keys.push_back(gptimage::SigningKey::load_pem(test_pem()));
    keys.push_back(gptimage::SigningKey::load_pem(gptimage::generate_rsa_key_pem(2048)));
    const json jwks = gptimage::jwks_json(keys);
    REQUIRE(jwks.contains("keys"));
    CHECK(jwks["keys"].size() == 2);
    CHECK(jwks["keys"][0].at("kid") != jwks["keys"][1].at("kid"));
}

TEST_CASE("algorithm confusion is rejected (the load-bearing property)") {
    auto verifier = make_verifier("https://gptimage.test", "https://gptimage.test/mcp");
    std::string err;

    SUBCASE("alg=none with an empty signature") {
        const std::string jwt = craft({{"alg", "none"}, {"typ", "JWT"}}, base_claims(), "");
        CHECK_FALSE(verifier.verify(jwt, err).has_value());
    }
    SUBCASE("alg=HS256 (RSA-public-key-as-HMAC-secret attack shape)") {
        // The verifier must reject on alg before ever treating the RSA public
        // key as an HMAC secret — so any HS256 token is refused outright.
        const std::string jwt = craft({{"alg", "HS256"}, {"typ", "JWT"},
                                       {"kid", test_key().kid()}}, base_claims());
        CHECK_FALSE(verifier.verify(jwt, err).has_value());
    }
    SUBCASE("alg present but non-string") {
        const std::string jwt = craft({{"alg", 123}, {"typ", "JWT"}}, base_claims());
        CHECK_FALSE(verifier.verify(jwt, err).has_value());  // clean reject, not a throw
    }
    SUBCASE("kid present but non-string") {
        const std::string jwt = craft({{"alg", "RS256"}, {"kid", 42}}, base_claims());
        CHECK_FALSE(verifier.verify(jwt, err).has_value());
    }
}

TEST_CASE("a token with no exp is rejected") {
    auto verifier = make_verifier("https://gptimage.test", "https://gptimage.test/mcp");
    json claims = base_claims();
    claims.erase("exp");
    const std::string jwt = gptimage::sign_jwt_rs256(test_key(), claims);  // validly signed
    std::string err;
    CHECK_FALSE(verifier.verify(jwt, err).has_value());
    CHECK(err == "missing exp");
}

TEST_CASE("empty configured audience or issuer fails closed") {
    const std::string jwt = gptimage::sign_jwt_rs256(test_key(), base_claims());
    std::string err;
    {
        auto v = make_verifier("https://gptimage.test", "");   // no audience configured
        CHECK_FALSE(v.verify(jwt, err).has_value());
    }
    {
        auto v = make_verifier("", "https://gptimage.test/mcp");  // no issuer configured
        CHECK_FALSE(v.verify(jwt, err).has_value());
    }
}

TEST_CASE("non-RSA PEM is rejected") {
    // An EC key must not load — the mint path is RS256-only.
    // (Generated with OpenSSL once; any P-256 private key works.)
    static const char* kEcPem =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n"
        "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n"
        "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n"
        "-----END PRIVATE KEY-----\n";
    CHECK_THROWS(gptimage::SigningKey::load_pem(kEcPem));
}
