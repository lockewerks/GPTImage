#pragma once

#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace gptimage {

// A verified JWT: the decoded claims plus the convenience subject. Produced only
// after signature + issuer/audience/expiry checks all pass.
struct VerifiedJwt {
    nlohmann::json claims;
    std::string    subject;   // the "sub" claim, for convenience
};

// Verifies RS256 JWTs against a JWKS (Keycloak). RS256 ONLY — "none" and HS*
// are rejected outright (the classic algorithm-confusion vuln). Keys are
// fetched from `jwks_url` and cached by `kid`; an unknown kid triggers one
// rate-limited refetch (key rotation). The JWKS fetcher is injectable so tests
// can supply static JSON without a network.
class JwtVerifier {
public:
    using Fetcher = std::function<std::string(const std::string& url)>;

    JwtVerifier(std::string issuer,
                std::string audience,
                std::string jwks_url,
                Fetcher fetcher = {},          // default: cpr GET
                int clock_skew_s = 60);

    // Verify a compact JWT (header.payload.signature). On success returns the
    // claims; on any failure returns nullopt and sets `err` to a short reason
    // (safe to log — contains no key material).
    std::optional<VerifiedJwt> verify(const std::string& compact, std::string& err);

private:
    std::string issuer_;
    std::string audience_;
    std::string jwks_url_;
    Fetcher     fetcher_;
    int         clock_skew_s_;
};

}  // namespace gptimage
