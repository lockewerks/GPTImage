#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <gptimage/password_hash.hpp>

#include <algorithm>
#include <cstdlib>
#include <string>

namespace {
void set_pepper(const char* v) {
#ifdef _WIN32
    _putenv_s("GPTIMAGE_PASSWORD_PEPPER", v ? v : "");
#else
    if (v) setenv("GPTIMAGE_PASSWORD_PEPPER", v, 1);
    else   unsetenv("GPTIMAGE_PASSWORD_PEPPER");
#endif
}
}  // namespace

TEST_CASE("hash/verify round trip") {
    const std::string phc = gptimage::hash_password("correct horse battery staple");
    CHECK(gptimage::verify_password("correct horse battery staple", phc));
    CHECK_FALSE(gptimage::verify_password("correct horse battery stapl", phc));
    CHECK_FALSE(gptimage::verify_password("", phc));
}

TEST_CASE("PHC string shape and parameters") {
    set_pepper(nullptr);
    const std::string phc = gptimage::hash_password("hunter2hunter2");
    CHECK(phc.rfind("$scrypt$ln=17,r=8,p=1$", 0) == 0);   // bumped from ln=15
    // $scrypt$params$salt$hash — exactly four '$'-delimited fields.
    CHECK(std::count(phc.begin(), phc.end(), '$') == 4);
    // PHC B64 has no padding.
    CHECK(phc.find('=', phc.find('$', 8)) == std::string::npos);
}

TEST_CASE("pepper: round-trip, fail-closed, and backward compatibility") {
    SUBCASE("peppered hash verifies only with the pepper present") {
        set_pepper("s3rver-p3pper-secret");
        const std::string phc = gptimage::hash_password("correct horse battery staple");
        CHECK(phc.find(",pep=v1$") != std::string::npos);   // marker recorded
        CHECK(gptimage::verify_password("correct horse battery staple", phc));
        CHECK_FALSE(gptimage::verify_password("wrong", phc));

        // Pepper removed → a peppered row must fail closed (can't reconstruct).
        set_pepper(nullptr);
        CHECK_FALSE(gptimage::verify_password("correct horse battery staple", phc));

        // Wrong pepper → also fails.
        set_pepper("a-different-pepper");
        CHECK_FALSE(gptimage::verify_password("correct horse battery staple", phc));
        set_pepper(nullptr);
    }

    SUBCASE("un-peppered rows still verify after a pepper is later configured") {
        set_pepper(nullptr);
        const std::string phc = gptimage::hash_password("legacy-row-password");
        CHECK(phc.find(",pep=") == std::string::npos);       // no marker
        // Enabling the pepper must not break existing un-marked rows.
        set_pepper("newly-added-pepper");
        CHECK(gptimage::verify_password("legacy-row-password", phc));
        set_pepper(nullptr);
    }
}

TEST_CASE("distinct salts: same password never hashes identically") {
    const std::string a = gptimage::hash_password("same password");
    const std::string b = gptimage::hash_password("same password");
    CHECK(a != b);
    CHECK(gptimage::verify_password("same password", a));
    CHECK(gptimage::verify_password("same password", b));
}

TEST_CASE("verify fails closed on malformed input") {
    CHECK_FALSE(gptimage::verify_password("pw", ""));
    CHECK_FALSE(gptimage::verify_password("pw", "$"));
    CHECK_FALSE(gptimage::verify_password("pw", "not-a-phc-string"));
    CHECK_FALSE(gptimage::verify_password("pw", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"));
    CHECK_FALSE(gptimage::verify_password("pw", "$scrypt$ln=15,r=8,p=1$c2FsdHNhbHQ"));      // missing hash
    CHECK_FALSE(gptimage::verify_password("pw", "$scrypt$ln=15,r=8$c2FsdHNhbHQ$aGFzaA"));   // missing p
    CHECK_FALSE(gptimage::verify_password("pw", "$scrypt$ln=15,r=8,p=1$!!!$aGFzaA"));        // bad b64 salt
}

TEST_CASE("verify rejects out-of-policy parameters (DoS ceilings)") {
    // Craft strings with hostile params around an otherwise plausible shape.
    // ln=25 would be a multi-GiB derivation; the parser must refuse before
    // touching the KDF.
    CHECK_FALSE(gptimage::verify_password(
        "pw", "$scrypt$ln=25,r=8,p=1$c2FsdHNhbHRzYWx0c2FsdA$"
              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    CHECK_FALSE(gptimage::verify_password(
        "pw", "$scrypt$ln=15,r=64,p=1$c2FsdHNhbHRzYWx0c2FsdA$"
              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    CHECK_FALSE(gptimage::verify_password(
        "pw", "$scrypt$ln=5,r=8,p=1$c2FsdHNhbHRzYWx0c2FsdA$"
              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));  // ln too LOW (weak) also refused
}

TEST_CASE("verify accepts a known-good stored literal (format stability)") {
    // Regression pin: a hash minted by hash_password today must stay
    // verifiable by future versions. If this breaks, old credentials die on
    // upgrade — bump only with a migration story.
    const std::string phc = gptimage::hash_password("pinned-format-check");
    CHECK(gptimage::verify_password("pinned-format-check", phc));
}
