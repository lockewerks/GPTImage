#include <gptimage/config_write.hpp>

#define TOML_EXCEPTIONS 1
#include <toml++/toml.hpp>

#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
#  include <windows.h>
#endif

namespace gptimage {

namespace {

std::string env_or_empty(const char* name) {
#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable : 4996)
#endif
    const char* v = std::getenv(name);
#ifdef _MSC_VER
#  pragma warning(pop)
#endif
    return v ? std::string(v) : std::string();
}

std::string read_file(const std::filesystem::path& p) {
    std::ifstream is(p, std::ios::binary);
    if (!is) throw std::runtime_error("config_write: cannot read " + p.string());
    std::ostringstream os;
    os << is.rdbuf();
    return os.str();
}

// Trim leading spaces/tabs; return the first non-blank, non-comment token's
// view of a line. Used to recognize section headers and key lines.
std::string_view lstrip(std::string_view s) {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    return s.substr(i);
}

// If `line` opens the section [name], return true. Matches "[name]" with
// optional surrounding whitespace; ignores dotted subsections here (the tray
// only writes top-level tables like [screenshots], [ingest], [identity]).
bool is_section_header(std::string_view line, std::string_view name) {
    std::string_view t = lstrip(line);
    if (t.empty() || t[0] != '[') return false;
    // Reject array-of-tables [[x]] — not a target of the scalar patcher.
    if (t.size() > 1 && t[1] == '[') return false;
    const size_t close = t.find(']');
    if (close == std::string_view::npos) return false;
    std::string_view inner = t.substr(1, close - 1);
    // strip inner whitespace
    while (!inner.empty() && (inner.front() == ' ' || inner.front() == '\t')) inner.remove_prefix(1);
    while (!inner.empty() && (inner.back() == ' ' || inner.back() == '\t')) inner.remove_suffix(1);
    return inner == name;
}

bool is_any_section_header(std::string_view line) {
    std::string_view t = lstrip(line);
    return !t.empty() && t[0] == '[';
}

// Key of an assignment line ("key = ...") or empty if the line isn't one.
std::string_view line_key(std::string_view line) {
    std::string_view t = lstrip(line);
    if (t.empty() || t[0] == '#' || t[0] == '[') return {};
    const size_t eq = t.find('=');
    if (eq == std::string_view::npos) return {};
    std::string_view k = t.substr(0, eq);
    while (!k.empty() && (k.back() == ' ' || k.back() == '\t')) k.remove_suffix(1);
    return k;
}

}  // namespace

std::string toml_quote(std::string_view s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

void atomic_write_text(const std::filesystem::path& path, std::string_view content) {
    const std::filesystem::path tmp = path.string() + ".tmp";
    {
        std::ofstream os(tmp, std::ios::binary | std::ios::trunc);
        if (!os) throw std::runtime_error("config_write: cannot open temp " + tmp.string());
        os.write(content.data(), static_cast<std::streamsize>(content.size()));
        os.flush();
        if (!os) throw std::runtime_error("config_write: write failed to " + tmp.string());
    }
#ifdef _WIN32
    if (!MoveFileExW(tmp.wstring().c_str(), path.wstring().c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        throw std::runtime_error("config_write: MoveFileEx failed for " + path.string());
    }
#else
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        throw std::runtime_error("config_write: rename failed for " + path.string());
    }
#endif
}

void patch_toml_keys(const std::filesystem::path& path,
                     std::string_view section,
                     const std::vector<std::pair<std::string, std::string>>& kv) {
    const std::string original = read_file(path);

    // Refuse to touch a file that doesn't already parse — we must be able to
    // round-trip it, and a broken file is a sign something else is wrong.
    try {
        toml::table check = toml::parse(original);
        (void)check;
    } catch (const toml::parse_error& e) {
        throw std::runtime_error(std::string("config_write: refusing to patch unparseable "
                                              "config: ") + e.description().data());
    }

    // Split into lines, remembering the newline style of the file (keep it).
    std::vector<std::string> lines;
    {
        std::string cur;
        for (char c : original) {
            if (c == '\n') { lines.push_back(cur); cur.clear(); }
            else cur.push_back(c);
        }
        lines.push_back(cur);  // trailing (possibly empty) segment
    }
    const bool crlf = !lines.empty() && !lines.front().empty() &&
                      lines.front().back() == '\r';
    (void)crlf;  // each line already retains its own trailing '\r' if present

    std::set<std::string> pending;
    for (const auto& [k, v] : kv) pending.insert(k);

    // Find the section's line range [start, end).
    int sec_start = -1, sec_end = static_cast<int>(lines.size());
    for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
        if (sec_start < 0) {
            if (is_section_header(lines[i], section)) sec_start = i;
        } else {
            if (is_any_section_header(lines[i])) { sec_end = i; break; }
        }
    }

    auto value_for = [&kv](std::string_view key) -> const std::string& {
        for (const auto& [k, v] : kv) if (k == key) return v;
        static const std::string empty;
        return empty;
    };

    auto assignment = [](const std::string& key, const std::string& val) {
        return key + " = " + val;
    };

    if (sec_start >= 0) {
        // Rewrite matching keys in place; track which we handled.
        for (int i = sec_start + 1; i < sec_end; ++i) {
            const std::string_view key = line_key(lines[i]);
            if (key.empty()) continue;
            const std::string kstr(key);
            if (pending.count(kstr)) {
                const bool cr = !lines[i].empty() && lines[i].back() == '\r';
                lines[i] = assignment(kstr, value_for(key)) + (cr ? "\r" : "");
                pending.erase(kstr);
            }
        }
        // Insert any still-pending keys just before the section ends. Skip
        // trailing blank lines so inserts sit with the section, not after it.
        int insert_at = sec_end;
        while (insert_at - 1 > sec_start &&
               lstrip(lines[insert_at - 1]).empty()) {
            --insert_at;
        }
        std::vector<std::string> adds;
        for (const auto& [k, v] : kv) {
            if (pending.count(k)) { adds.push_back(assignment(k, v)); pending.erase(k); }
        }
        lines.insert(lines.begin() + insert_at, adds.begin(), adds.end());
    } else {
        // Section absent: append it (with a preceding blank line) at EOF.
        if (!lines.empty() && !lstrip(lines.back()).empty()) lines.emplace_back("");
        lines.emplace_back("[" + std::string(section) + "]");
        for (const auto& [k, v] : kv) lines.push_back(assignment(k, v));
    }

    // Reassemble with '\n' (each line kept its own '\r' if the file was CRLF).
    std::string out;
    for (size_t i = 0; i < lines.size(); ++i) {
        out += lines[i];
        if (i + 1 < lines.size()) out.push_back('\n');
    }

    // Verify the result still parses before committing — a patch that produced
    // invalid TOML must never reach disk.
    try {
        toml::table check = toml::parse(out);
        (void)check;
    } catch (const toml::parse_error& e) {
        throw std::runtime_error(std::string("config_write: patch would produce invalid "
                                              "TOML, aborting: ") + e.description().data());
    }

    atomic_write_text(path, out);
}

std::filesystem::path state_dir() {
    std::filesystem::path dir;
#ifdef _WIN32
    std::string pd = env_or_empty("ProgramData");
    if (pd.empty()) pd = "C:\\ProgramData";
    dir = std::filesystem::path(pd) / "GPTImage" / "state";
#else
    dir = std::filesystem::temp_directory_path() / "gptimage-state";
#endif
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

}  // namespace gptimage
