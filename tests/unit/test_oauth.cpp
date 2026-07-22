#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "oauth.hpp"

#include <string>
#include <vector>

TEST_CASE("PKCE S256 matches the RFC 7636 appendix B vector") {
    // Verifier and its published S256 transform, straight from the RFC.
    const std::string verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const std::string challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    CHECK(gptimage::oauth_s256_challenge(verifier) == challenge);
}

TEST_CASE("PKCE string validation: length and charset bounds") {
    const std::string ok(43, 'a');
    CHECK(gptimage::oauth_valid_pkce_string(ok));
    CHECK(gptimage::oauth_valid_pkce_string(std::string(128, 'A')));
    CHECK(gptimage::oauth_valid_pkce_string("abcDEF123-._~" + std::string(30, 'x')));

    CHECK_FALSE(gptimage::oauth_valid_pkce_string(std::string(42, 'a')));   // too short
    CHECK_FALSE(gptimage::oauth_valid_pkce_string(std::string(129, 'a')));  // too long
    CHECK_FALSE(gptimage::oauth_valid_pkce_string(std::string(43, '+')));   // bad charset
    CHECK_FALSE(gptimage::oauth_valid_pkce_string(std::string(40, 'a') + "a=b"));
}

TEST_CASE("https host extraction") {
    CHECK(gptimage::oauth_https_host_of("https://claude.ai/api/mcp/auth_callback") == "claude.ai");
    CHECK(gptimage::oauth_https_host_of("https://ChatGPT.com/callback") == "chatgpt.com");
    CHECK(gptimage::oauth_https_host_of("https://api.openai.com:8443/cb") == "api.openai.com");
    CHECK(gptimage::oauth_https_host_of("https://host.example") == "host.example");

    CHECK(gptimage::oauth_https_host_of("http://claude.ai/cb").empty());       // not https
    CHECK(gptimage::oauth_https_host_of("claude.ai/cb").empty());              // no scheme
    CHECK(gptimage::oauth_https_host_of("https://user@evil.com/cb").empty());  // userinfo
    CHECK(gptimage::oauth_https_host_of("").empty());
}

TEST_CASE("JSON nesting-depth guard") {
    CHECK(gptimage::json_within_depth("{}", 64));
    CHECK(gptimage::json_within_depth(R"({"a":{"b":[1,2,3]}})", 64));
    CHECK(gptimage::json_within_depth("", 64));
    // Brackets inside strings don't count toward depth.
    CHECK(gptimage::json_within_depth(R"({"k":"[[[[[[[["})", 4));

    // A ladder deeper than the limit is rejected.
    std::string deep(200, '[');
    CHECK_FALSE(gptimage::json_within_depth(deep, 64));
    // Exactly at the limit passes; one deeper fails.
    CHECK(gptimage::json_within_depth(std::string(64, '['), 64));
    CHECK_FALSE(gptimage::json_within_depth(std::string(65, '['), 64));
}

TEST_CASE("redirect-host allowlist: exact + subdomain, no lookalikes") {
    const std::vector<std::string> allow = {"claude.ai", "chatgpt.com"};

    CHECK(gptimage::oauth_host_allowed("claude.ai", allow));
    CHECK(gptimage::oauth_host_allowed("api.claude.ai", allow));
    CHECK(gptimage::oauth_host_allowed("chatgpt.com", allow));
    CHECK(gptimage::oauth_host_allowed("connector.chatgpt.com", allow));

    CHECK_FALSE(gptimage::oauth_host_allowed("notclaude.ai", allow));
    CHECK_FALSE(gptimage::oauth_host_allowed("claude.ai.evil.com", allow));
    CHECK_FALSE(gptimage::oauth_host_allowed("evil.com", allow));
    CHECK_FALSE(gptimage::oauth_host_allowed("", allow));

    // Empty allowlist = explicitly allow everything (config escape hatch).
    CHECK(gptimage::oauth_host_allowed("anything.example", {}));
}
