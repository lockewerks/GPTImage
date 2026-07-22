#include <gptimage/realm.hpp>

#include <algorithm>
#include <sstream>

namespace gptimage {

using nlohmann::json;

namespace {

// Append `realm` to `out` unless already present (small N — linear is fine).
void push_unique(std::vector<std::string>& out, const std::string& realm) {
    if (std::find(out.begin(), out.end(), realm) == out.end()) out.push_back(realm);
}

int sensitivity_rank(const std::string& s) {
    if (s == "low")        return 0;
    if (s == "medium")     return 1;
    if (s == "high")       return 2;
    if (s == "restricted") return 3;
    return 3;  // unknown/empty ⇒ no ceiling
}

}  // namespace

RealmGrant local_grant() {
    RealmGrant g;
    g.principal  = "local";
    g.home_realm = "default";
    g.read_all   = true;
    g.write_all  = true;
    // no max_sensitivity ceiling
    return g;
}

bool grant_can_read(const RealmGrant& grant, const std::string& realm) {
    if (grant.read_all) return true;
    if (realm == grant.home_realm) return true;
    return std::find(grant.read_realms.begin(), grant.read_realms.end(), realm) !=
           grant.read_realms.end();
}

bool grant_can_write(const RealmGrant& grant, const std::string& realm) {
    if (grant.write_all) return true;
    if (realm == grant.home_realm) return true;
    return std::find(grant.write_realms.begin(), grant.write_realms.end(), realm) !=
           grant.write_realms.end();
}

int grant_sensitivity_cap(const RealmGrant& grant) {
    return sensitivity_rank(grant.max_sensitivity);
}

bool resolve_read_realms(const RealmGrant& grant,
                         const json& args,
                         std::vector<std::string>& out,
                         std::string& err) {
    out.clear();
    err.clear();

    const bool has_realms =
        args.contains("realms") && args["realms"].is_array() && !args["realms"].empty();

    // Reject a present-but-malformed "realms" (object, string, number...).
    if (args.contains("realms") && !args["realms"].is_array()) {
        err = "realms must be an array of realm names";
        return false;
    }

    if (!has_realms) {
        // Default scope: the caller's home realm plus the shared commons.
        push_unique(out, grant.home_realm);
        push_unique(out, "commons");
        return true;
    }

    std::vector<std::string> requested;
    for (const auto& v : args["realms"]) {
        if (!v.is_string()) {
            err = "realms must be an array of realm names";
            return false;
        }
        requested.push_back(v.get<std::string>());
    }

    // Wildcard: only the read-all principal may request every realm. Returning
    // an empty set signals "no realm predicate" to the SQL builders.
    const bool wildcard =
        requested.size() == 1 && requested.front() == "*";
    if (wildcard) {
        if (!grant.read_all) {
            err = "not authorized to read all realms";
            return false;
        }
        out.clear();
        return true;
    }

    for (const auto& realm : requested) {
        if (realm == "*") {
            err = "realms cannot mix \"*\" with explicit realm names";
            return false;
        }
        if (!grant_can_read(grant, realm)) {
            err = "not authorized to read realm '" + realm + "'";
            return false;
        }
        push_unique(out, realm);
    }
    return true;
}

bool resolve_write_realms(const RealmGrant& grant,
                          std::vector<std::string>& out,
                          std::string& err) {
    out.clear();
    err.clear();

    if (grant.write_all) {
        // Empty ⇒ no predicate; the write touches whatever realm the target is.
        return true;
    }

    // home_realm is always writable; union it with the explicit write grant.
    // Guard against a pathological empty home_realm — an empty entry would be a
    // useless predicate ({""} matches nothing) and must not pass as authority.
    if (!grant.home_realm.empty()) push_unique(out, grant.home_realm);
    for (const auto& r : grant.write_realms) push_unique(out, r);

    if (out.empty()) {
        err = "no write authority for any realm";
        return false;
    }
    return true;
}

std::string format_text_array(const std::vector<std::string>& items) {
    std::ostringstream os;
    os << '{';
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) os << ',';
        os << '"';
        for (char c : items[i]) {
            if (c == '"' || c == '\\') os << '\\';
            os << c;
        }
        os << '"';
    }
    os << '}';
    return os.str();
}

}  // namespace gptimage
