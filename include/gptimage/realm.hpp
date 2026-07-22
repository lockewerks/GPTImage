#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace gptimage {

// A principal's authority over realms. Resolved once per request — from a
// static API-token row, a verified OAuth JWT, or local_grant() for stdio /
// loopback callers — and threaded read-only through tool execution. Realm
// scoping is enforced in application code (the SQL predicates the tools build),
// not by Postgres row-level security.
struct RealmGrant {
    std::string principal;                  // "operator", "local", ...
    std::string home_realm = "default";     // never empty; default read/write target
    bool read_all  = false;                 // wildcard: may read every realm
    bool write_all = false;                 // wildcard: may write every realm
    std::vector<std::string> read_realms;   // explicit read grant (ignored if read_all)
    std::vector<std::string> write_realms;  // explicit write grant (ignored if write_all)
    // Read-side sensitivity ceiling: results above this rank are filtered out
    // regardless of the request's max_sensitivity. One of low|medium|high|
    // restricted; empty ⇒ no ceiling (treated as "restricted").
    std::string max_sensitivity;
};

// The implicit grant for stdio / loopback callers: the operator, full
// authority, no sensitivity ceiling. Used wherever there is no per-request
// credential to resolve (the stdio transport, the CLI).
RealmGrant local_grant();

// Membership tests against a grant.
bool grant_can_read(const RealmGrant& grant, const std::string& realm);
bool grant_can_write(const RealmGrant& grant, const std::string& realm);

// The grant's effective read-sensitivity ceiling as an integer rank
// (low=0 … restricted=3). Empty max_sensitivity ⇒ 3 (no ceiling).
int grant_sensitivity_cap(const RealmGrant& grant);

// Resolve the realm set a read-path tool (search / recall / context) scopes to,
// given the request `args`:
//   - no "realms" key (or empty/[]):  {home_realm, "commons"} deduped
//   - "realms" == ["*"]:              {} (empty ⇒ no predicate) IFF read_all,
//                                     else error
//   - "realms" == [names...]:         validated — every name must be readable;
//                                     returned deduped
// Returns true and fills `out` on success; false and sets `err` on a grant
// violation or malformed "realms". An empty `out` means "no realm predicate"
// (the SQL treats cardinality 0 as unrestricted) and is produced ONLY for the
// wildcard-with-read_all case.
bool resolve_read_realms(const RealmGrant& grant,
                         const nlohmann::json& args,
                         std::vector<std::string>& out,
                         std::string& err);

// Resolve the realm set a write-path tool (pin / forget) may act within:
//   - write_all:  {} (empty ⇒ no predicate, i.e. every realm)
//   - else:       write_realms (must be non-empty)
// Returns false and sets `err` if the grant authorizes no writes at all.
bool resolve_write_realms(const RealmGrant& grant,
                          std::vector<std::string>& out,
                          std::string& err);

// Format a string vector as a Postgres text[] array literal — e.g.
// {"archon","commons"} — safe to bind as one $N parameter of type text[].
// Elements are double-quoted with internal " and \ escaped. Empty ⇒ "{}".
std::string format_text_array(const std::vector<std::string>& items);

}  // namespace gptimage
