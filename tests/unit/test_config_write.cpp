#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <gptimage/config_write.hpp>

#define TOML_EXCEPTIONS 1
#include <toml++/toml.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

namespace {

fs::path write_temp(const std::string& name, const std::string& body) {
    auto p = fs::temp_directory_path() / ("gptimage_cw_" + name + ".toml");
    std::ofstream os(p, std::ios::binary | std::ios::trunc);
    os << body;
    return p;
}

std::string read_all(const fs::path& p) {
    std::ifstream is(p, std::ios::binary);
    std::ostringstream os;
    os << is.rdbuf();
    return os.str();
}

}  // namespace

TEST_CASE("patch replaces a value and preserves comments + other keys") {
    auto p = write_temp("basic", R"([screenshots]
# capture cadence — lower means more cost
interval_ms = 30000
enabled = true  # trailing comment stays
dhash_distance_threshold = 8
)");
    gptimage::patch_toml_keys(p, "screenshots", {{"interval_ms", "10000"}});
    const std::string out = read_all(p);

    CHECK(out.find("interval_ms = 10000") != std::string::npos);
    CHECK(out.find("interval_ms = 30000") == std::string::npos);
    CHECK(out.find("# capture cadence") != std::string::npos);        // comment kept
    CHECK(out.find("enabled = true  # trailing comment stays") != std::string::npos);
    CHECK(out.find("dhash_distance_threshold = 8") != std::string::npos);

    auto t = toml::parse(out);
    CHECK(t["screenshots"]["interval_ms"].value<int64_t>() == 10000);
    fs::remove(p);
}

TEST_CASE("patch inserts a missing key into an existing section") {
    auto p = write_temp("insert", R"([ingest]
inbox_path = "C:/old"
)");
    gptimage::patch_toml_keys(p, "ingest",
        {{"inbox_path", "\"C:/new\""}, {"poll_interval_ms", "500"}});
    auto t = toml::parse(read_all(p));
    CHECK(t["ingest"]["inbox_path"].value<std::string>() == "C:/new");
    CHECK(t["ingest"]["poll_interval_ms"].value<int64_t>() == 500);
    fs::remove(p);
}

TEST_CASE("patch appends a missing section without disturbing others") {
    auto p = write_temp("append", R"([database]
dbname = "d"
user = "u"
)");
    gptimage::patch_toml_keys(p, "identity",
        {{"principal", "\"nyx\""}, {"realm", "\"nyx\""}});
    auto t = toml::parse(read_all(p));
    CHECK(t["database"]["dbname"].value<std::string>() == "d");
    CHECK(t["identity"]["principal"].value<std::string>() == "nyx");
    CHECK(t["identity"]["realm"].value<std::string>() == "nyx");
    fs::remove(p);
}

TEST_CASE("a hand-added [oracle] section survives a [screenshots] patch") {
    auto p = write_temp("survive", R"([screenshots]
interval_ms = 30000

# The operator hand-added this; it must never be lost.
[oracle]
host = "127.0.0.1"
dbname = "oracle"
)");
    gptimage::patch_toml_keys(p, "screenshots", {{"interval_ms", "5000"}});
    const std::string out = read_all(p);
    CHECK(out.find("[oracle]") != std::string::npos);
    CHECK(out.find("The operator hand-added this") != std::string::npos);
    CHECK(out.find("dbname = \"oracle\"") != std::string::npos);
    auto t = toml::parse(out);
    CHECK(t["screenshots"]["interval_ms"].value<int64_t>() == 5000);
    CHECK(t["oracle"]["host"].value<std::string>() == "127.0.0.1");
    fs::remove(p);
}

TEST_CASE("patch refuses to clobber an unparseable file") {
    auto p = write_temp("broken", "this is [not valid = toml at all \n [[[");
    CHECK_THROWS(gptimage::patch_toml_keys(p, "x", {{"k", "1"}}));
    fs::remove(p);
}

TEST_CASE("atomic_write_text replaces contents") {
    auto p = write_temp("atomic", "before\n");
    gptimage::atomic_write_text(p, "after\n");
    CHECK(read_all(p) == "after\n");
    fs::remove(p);
}

TEST_CASE("toml_quote escapes quotes and backslashes") {
    CHECK(gptimage::toml_quote("plain") == "\"plain\"");
    CHECK(gptimage::toml_quote("C:\\path") == "\"C:\\\\path\"");
    CHECK(gptimage::toml_quote("say \"hi\"") == "\"say \\\"hi\\\"\"");
}
