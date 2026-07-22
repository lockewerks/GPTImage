#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <gptimage/realm.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <vector>

using gptimage::RealmGrant;
using nlohmann::json;

namespace {

// nyx-style grant: home realm + commons, no wildcard, medium ceiling.
RealmGrant nyx_grant() {
    RealmGrant g;
    g.principal       = "nyx";
    g.home_realm      = "nyx";
    g.read_all        = false;
    g.write_all       = false;
    g.read_realms     = {"nyx", "commons"};
    g.write_realms    = {"nyx", "commons"};
    g.max_sensitivity = "medium";
    return g;
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

}  // namespace

TEST_CASE("local_grant is the full-authority operator") {
    auto g = gptimage::local_grant();
    CHECK(g.read_all);
    CHECK(g.write_all);
    CHECK(g.home_realm == "default");
    CHECK(gptimage::grant_can_read(g, "anything"));
    CHECK(gptimage::grant_can_write(g, "anything"));
    // No ceiling -> restricted rank 3.
    CHECK(gptimage::grant_sensitivity_cap(g) == 3);
}

TEST_CASE("default read scope is home + commons, deduped") {
    auto g = nyx_grant();
    std::vector<std::string> out;
    std::string err;
    REQUIRE(gptimage::resolve_read_realms(g, json::object(), out, err));
    CHECK(err.empty());
    CHECK(out.size() == 2);
    CHECK(contains(out, "nyx"));
    CHECK(contains(out, "commons"));
}

TEST_CASE("home == commons dedupes to a single entry") {
    RealmGrant g = nyx_grant();
    g.home_realm = "commons";
    std::vector<std::string> out;
    std::string err;
    REQUIRE(gptimage::resolve_read_realms(g, json::object(), out, err));
    CHECK(out.size() == 1);
    CHECK(out[0] == "commons");
}

TEST_CASE("explicit realms within grant are honored") {
    auto g = nyx_grant();
    json args = {{"realms", json::array({"commons"})}};
    std::vector<std::string> out;
    std::string err;
    REQUIRE(gptimage::resolve_read_realms(g, args, out, err));
    CHECK(out.size() == 1);
    CHECK(out[0] == "commons");
}

TEST_CASE("explicit realm outside grant is rejected") {
    auto g = nyx_grant();
    json args = {{"realms", json::array({"archon"})}};
    std::vector<std::string> out;
    std::string err;
    CHECK_FALSE(gptimage::resolve_read_realms(g, args, out, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("empty realms array falls back to default scope") {
    auto g = nyx_grant();
    json args = {{"realms", json::array()}};
    std::vector<std::string> out;
    std::string err;
    REQUIRE(gptimage::resolve_read_realms(g, args, out, err));
    CHECK(out.size() == 2);  // home + commons
}

TEST_CASE("malformed realms (non-array) is rejected") {
    auto g = nyx_grant();
    json args = {{"realms", "commons"}};  // string, not array
    std::vector<std::string> out;
    std::string err;
    CHECK_FALSE(gptimage::resolve_read_realms(g, args, out, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("wildcard requires read_all") {
    json args = {{"realms", json::array({"*"})}};
    std::vector<std::string> out;
    std::string err;

    SUBCASE("read_all principal: wildcard -> empty (no predicate)") {
        auto g = gptimage::local_grant();
        REQUIRE(gptimage::resolve_read_realms(g, args, out, err));
        CHECK(out.empty());  // empty == "no realm predicate" == all realms
    }
    SUBCASE("scoped principal: wildcard rejected") {
        auto g = nyx_grant();
        CHECK_FALSE(gptimage::resolve_read_realms(g, args, out, err));
        CHECK_FALSE(err.empty());
    }
}

TEST_CASE("wildcard cannot be mixed with explicit realms") {
    auto g = gptimage::local_grant();
    json args = {{"realms", json::array({"*", "archon"})}};
    std::vector<std::string> out;
    std::string err;
    CHECK_FALSE(gptimage::resolve_read_realms(g, args, out, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("write realm resolution") {
    SUBCASE("write_all -> empty (no predicate)") {
        auto g = gptimage::local_grant();
        std::vector<std::string> out;
        std::string err;
        REQUIRE(gptimage::resolve_write_realms(g, out, err));
        CHECK(out.empty());
    }
    SUBCASE("scoped principal -> home + explicit writes") {
        auto g = nyx_grant();
        std::vector<std::string> out;
        std::string err;
        REQUIRE(gptimage::resolve_write_realms(g, out, err));
        CHECK(contains(out, "nyx"));
        CHECK(contains(out, "commons"));
    }
    SUBCASE("no write authority is rejected") {
        RealmGrant g;
        g.principal    = "reader";
        g.home_realm   = "";  // pathological: nothing writable
        g.write_all    = false;
        g.write_realms = {};
        std::vector<std::string> out;
        std::string err;
        CHECK_FALSE(gptimage::resolve_write_realms(g, out, err));
    }
}

TEST_CASE("sensitivity cap maps to rank") {
    RealmGrant g;
    g.max_sensitivity = "low";    CHECK(gptimage::grant_sensitivity_cap(g) == 0);
    g.max_sensitivity = "medium"; CHECK(gptimage::grant_sensitivity_cap(g) == 1);
    g.max_sensitivity = "high";   CHECK(gptimage::grant_sensitivity_cap(g) == 2);
    g.max_sensitivity = "restricted"; CHECK(gptimage::grant_sensitivity_cap(g) == 3);
    g.max_sensitivity = "";       CHECK(gptimage::grant_sensitivity_cap(g) == 3);
}

TEST_CASE("format_text_array produces a valid PG literal") {
    CHECK(gptimage::format_text_array({}) == "{}");
    CHECK(gptimage::format_text_array({"nyx"}) == "{\"nyx\"}");
    CHECK(gptimage::format_text_array({"nyx", "commons"}) == "{\"nyx\",\"commons\"}");
    // Defensive escaping of embedded quote / backslash.
    CHECK(gptimage::format_text_array({"a\"b"}) == "{\"a\\\"b\"}");
}
