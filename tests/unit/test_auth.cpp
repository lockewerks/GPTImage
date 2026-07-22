#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <gptimage/auth.hpp>
#include <gptimage/realm.hpp>

#include <nlohmann/json.hpp>

#include <set>
#include <string>

using nlohmann::json;

TEST_CASE("parse_bearer handles scheme variants") {
    std::string tok;

    CHECK(gptimage::parse_bearer("Bearer abc123", tok));
    CHECK(tok == "abc123");

    CHECK(gptimage::parse_bearer("bearer abc123", tok));   // lowercase scheme
    CHECK(tok == "abc123");

    CHECK(gptimage::parse_bearer("BEARER   xyz  ", tok));  // padding both sides
    CHECK(tok == "xyz");

    CHECK(gptimage::parse_bearer("  Bearer t0ken", tok));  // leading ws
    CHECK(tok == "t0ken");

    CHECK_FALSE(gptimage::parse_bearer("", tok));
    CHECK_FALSE(gptimage::parse_bearer("Bearer", tok));        // no token
    CHECK_FALSE(gptimage::parse_bearer("Bearer ", tok));       // empty token
    CHECK_FALSE(gptimage::parse_bearer("Basic abc", tok));     // wrong scheme
    CHECK_FALSE(gptimage::parse_bearer("Bearerabc", tok));     // no space
}

TEST_CASE("sha256_hex matches known vectors") {
    CHECK(gptimage::sha256_hex("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(gptimage::sha256_hex("abc") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("constant_time_equals") {
    CHECK(gptimage::constant_time_equals("abcdef", "abcdef"));
    CHECK_FALSE(gptimage::constant_time_equals("abcdef", "abcdeg"));
    CHECK_FALSE(gptimage::constant_time_equals("abc", "abcd"));  // length differs
    CHECK(gptimage::constant_time_equals("", ""));
}

TEST_CASE("generate_token shape and uniqueness") {
    std::set<std::string> seen;
    for (int i = 0; i < 50; ++i) {
        const std::string t = gptimage::generate_token();
        CHECK(t.rfind("gpt_", 0) == 0);            // prefix
        CHECK(t.size() > 40);                       // gpt_ + ~43 base64url chars
        // body is base64url (no +,/,= padding)
        for (char c : t.substr(4)) {
            const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '-' || c == '_';
            CHECK(ok);
        }
        CHECK(seen.insert(t).second);               // unique
    }
}

TEST_CASE("grant_from_json: wildcard read/write") {
    json g = {{"home", "archon"}, {"read", {"*"}}, {"write", {"*"}}};
    gptimage::RealmGrant grant;
    std::string err;
    REQUIRE(gptimage::grant_from_json(g, "archon", grant, err));
    CHECK(grant.principal == "archon");
    CHECK(grant.home_realm == "archon");
    CHECK(grant.read_all);
    CHECK(grant.write_all);
}

TEST_CASE("grant_from_json: explicit lists + sensitivity ceiling") {
    json g = {{"home", "nyx"},
              {"read", {"nyx", "commons"}},
              {"write", {"nyx", "commons"}},
              {"max_sensitivity", "medium"}};
    gptimage::RealmGrant grant;
    std::string err;
    REQUIRE(gptimage::grant_from_json(g, "nyx", grant, err));
    CHECK_FALSE(grant.read_all);
    CHECK(grant.read_realms.size() == 2);
    CHECK(grant.max_sensitivity == "medium");
    CHECK(gptimage::grant_sensitivity_cap(grant) == 1);
    // Honors the scope: nyx may read commons, not archon.
    CHECK(gptimage::grant_can_read(grant, "commons"));
    CHECK_FALSE(gptimage::grant_can_read(grant, "archon"));
}

TEST_CASE("grant_from_json fails closed") {
    gptimage::RealmGrant grant;
    std::string err;

    SUBCASE("missing home") {
        json g = {{"read", {"nyx"}}};
        CHECK_FALSE(gptimage::grant_from_json(g, "nyx", grant, err));
        CHECK_FALSE(err.empty());
    }
    SUBCASE("non-object") {
        json g = json::array({"nope"});
        CHECK_FALSE(gptimage::grant_from_json(g, "nyx", grant, err));
    }
    SUBCASE("non-string realm in list") {
        json g = {{"home", "nyx"}, {"read", {1, 2, 3}}};
        CHECK_FALSE(gptimage::grant_from_json(g, "nyx", grant, err));
    }
}

TEST_CASE("resolve_jwt_principal") {
    gptimage::AuthConfig cfg;  // jwt_principal_claim defaults to "sub"

    SUBCASE("plain sub claim passes through") {
        auto p = gptimage::resolve_jwt_principal(cfg, json{{"sub", "archon"}});
        REQUIRE(p.has_value());
        CHECK(*p == "archon");
    }
    SUBCASE("subject map rewrites UUID subjects to principal names") {
        cfg.jwt_subject_map = {{"3f6a1c2e-dead-beef-0000-000000000001", "nyx"}};
        auto p = gptimage::resolve_jwt_principal(
            cfg, json{{"sub", "3f6a1c2e-dead-beef-0000-000000000001"}});
        REQUIRE(p.has_value());
        CHECK(*p == "nyx");
        // Unmapped subjects still pass through untranslated.
        auto q = gptimage::resolve_jwt_principal(cfg, json{{"sub", "archon"}});
        REQUIRE(q.has_value());
        CHECK(*q == "archon");
    }
    SUBCASE("custom principal claim") {
        cfg.jwt_principal_claim = "preferred_username";
        auto p = gptimage::resolve_jwt_principal(
            cfg, json{{"sub", "uuid-here"}, {"preferred_username", "archon"}});
        REQUIRE(p.has_value());
        CHECK(*p == "archon");
    }
    SUBCASE("fails closed: missing, empty, or non-string claim") {
        CHECK_FALSE(gptimage::resolve_jwt_principal(cfg, json::object()).has_value());
        CHECK_FALSE(gptimage::resolve_jwt_principal(cfg, json{{"sub", ""}}).has_value());
        CHECK_FALSE(gptimage::resolve_jwt_principal(cfg, json{{"sub", 42}}).has_value());
    }
}
