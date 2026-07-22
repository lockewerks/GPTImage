#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <gptimage/config.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

namespace {

// Writes `body` to a uniquely named TOML file in the temp dir and returns the
// path. `name` is a human-readable suffix so failed tests leave artifacts that
// map to their case name.
fs::path write_temp_toml(const std::string& name, const std::string& body) {
    auto path = fs::temp_directory_path() / ("gptimage_test_" + name + ".toml");
    std::ofstream os(path);
    os << body;
    os.close();
    return path;
}

void set_env(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
#else
    setenv(k, v, 1);
#endif
}

}  // namespace

TEST_CASE("missing file throws") {
    auto p = fs::temp_directory_path() / "gptimage_does_not_exist_xyz.toml";
    CHECK_THROWS(gptimage::load_config(p));
}

TEST_CASE("minimal valid config parses with defaults") {
    auto p = write_temp_toml("minimal", R"(
[database]
host = "localhost"
port = 5432
dbname = "test"
user = "tester"
)");
    auto cfg = gptimage::load_config(p);
    CHECK(cfg.database.host   == "localhost");
    CHECK(cfg.database.port   == 5432);
    CHECK(cfg.database.dbname == "test");
    CHECK(cfg.database.user   == "tester");
    CHECK(cfg.database.schema == "gptimage");
    // Defaults for the image backend.
    CHECK(cfg.image.model           == "gpt-image-2");
    CHECK(cfg.image.default_size     == "1024x1024");
    CHECK(cfg.image.default_quality  == "high");
    CHECK(cfg.image.default_format   == "png");
    CHECK(cfg.image.max_n            == 4);
    CHECK(cfg.mcp.transport == "stdio");
}

TEST_CASE("missing required database fields throw") {
    SUBCASE("no dbname") {
        auto p = write_temp_toml("no_dbname", R"(
[database]
user = "tester"
)");
        CHECK_THROWS(gptimage::load_config(p));
    }
    SUBCASE("no user") {
        auto p = write_temp_toml("no_user", R"(
[database]
dbname = "test"
)");
        CHECK_THROWS(gptimage::load_config(p));
    }
    SUBCASE("no [database] section at all") {
        auto p = write_temp_toml("no_db_section", R"(
[image]
model = "gpt-image-2"
)");
        CHECK_THROWS(gptimage::load_config(p));
    }
}

TEST_CASE("[image] overrides and env key resolution") {
    set_env("GPTIMAGE_TEST_OAI_KEY", "sk-test-123");
    auto p = write_temp_toml("image", R"(
[database]
dbname = "test"
user = "tester"

[image]
model            = "gpt-image-99"
api_key_env      = "GPTIMAGE_TEST_OAI_KEY"
default_size     = "1536x1024"
default_quality  = "low"
default_format   = "webp"
moderation       = "auto"
max_n            = 2
timeout_s        = 42
)");
    auto cfg = gptimage::load_config(p);
    CHECK(cfg.image.model          == "gpt-image-99");
    CHECK(cfg.image.default_size    == "1536x1024");
    CHECK(cfg.image.default_quality == "low");
    CHECK(cfg.image.default_format  == "webp");
    CHECK(cfg.image.moderation      == "auto");
    CHECK(cfg.image.max_n           == 2);
    CHECK(cfg.image.timeout_s       == 42);
    // The key is resolved from the named env var, never stored in the TOML.
    CHECK(cfg.image.api_key == "sk-test-123");
}

TEST_CASE("api key resolves from default env even without an [image] section") {
    set_env("OPENAI_API_KEY", "sk-ambient-xyz");
    auto p = write_temp_toml("ambient_key", R"(
[database]
dbname = "test"
user = "tester"
)");
    auto cfg = gptimage::load_config(p);
    CHECK(cfg.image.api_key_env == "OPENAI_API_KEY");
    CHECK(cfg.image.api_key     == "sk-ambient-xyz");
}

TEST_CASE("[mcp] parses transport and binds") {
    auto p = write_temp_toml("mcp", R"(
[database]
dbname = "test"
user = "tester"

[mcp]
transport = "http"
http_bind = "127.0.0.1:19999"
)");
    auto cfg = gptimage::load_config(p);
    CHECK(cfg.mcp.transport == "http");
    CHECK(cfg.mcp.http_bind == "127.0.0.1:19999");
}

TEST_CASE("[auth.oauth] derives jwt issuer/audience from the mint side") {
    auto p = write_temp_toml("oauth", R"(
[database]
dbname = "test"
user = "tester"

[auth]
enabled = true

[auth.oauth]
enabled          = true
issuer           = "https://img.example.com"
resource         = "https://img.example.com/mcp"
signing_key_path = "/tmp/does-not-need-to-exist.pem"
)");
    auto cfg = gptimage::load_config(p);
    CHECK(cfg.auth.oauth.enabled);
    // Verify side is derived from the mint side so they cannot drift.
    CHECK(cfg.auth.jwt_issuer   == "https://img.example.com");
    CHECK(cfg.auth.jwt_audience == "https://img.example.com/mcp");
    CHECK(cfg.auth.resource_metadata_url ==
          "https://img.example.com/.well-known/oauth-protected-resource/mcp");
}

TEST_CASE("oauth enabled without issuer fails closed") {
    auto p = write_temp_toml("oauth_bad", R"(
[database]
dbname = "test"
user = "tester"

[auth]
[auth.oauth]
enabled = true
)");
    CHECK_THROWS(gptimage::load_config(p));
}

TEST_CASE("issuer with a trailing slash is rejected") {
    auto p = write_temp_toml("oauth_slash", R"(
[database]
dbname = "test"
user = "tester"

[auth]
[auth.oauth]
enabled          = true
issuer           = "https://img.example.com/"
resource         = "https://img.example.com/mcp"
signing_key_path = "/tmp/x.pem"
)");
    CHECK_THROWS(gptimage::load_config(p));
}

TEST_CASE("a JWT issuer without an audience is rejected") {
    auto p = write_temp_toml("jwt_no_aud", R"(
[database]
dbname = "test"
user = "tester"

[auth]
jwt_issuer = "https://external-idp.example.com"
)");
    CHECK_THROWS(gptimage::load_config(p));
}

TEST_CASE("[[auth.principals]] parse into the grant template") {
    auto p = write_temp_toml("principals", R"(
[database]
dbname = "test"
user = "tester"

[auth]
[[auth.principals]]
name         = "operator"
home_realm   = "default"
read_realms  = ["*"]
write_realms = ["*"]
)");
    auto cfg = gptimage::load_config(p);
    REQUIRE(cfg.auth.principals.size() == 1);
    CHECK(cfg.auth.principals[0].name == "operator");
    CHECK(cfg.auth.principals[0].home_realm == "default");
    REQUIRE(cfg.auth.principals[0].read_realms.size() == 1);
    CHECK(cfg.auth.principals[0].read_realms[0] == "*");
}
