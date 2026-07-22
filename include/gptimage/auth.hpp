#pragma once

#include <gptimage/config.hpp>
#include <gptimage/realm.hpp>

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace gptimage {

// Generate a new opaque bearer token: "gpt_" + base64url(32 random bytes),
// cryptographically random via OpenSSL RAND_bytes. Throws on RNG failure.
std::string generate_token();

// Lowercase-hex SHA-256 of `data`. Bearer tokens are stored and looked up by
// this hash — the plaintext is never persisted.
std::string sha256_hex(std::string_view data);

// Constant-time equality. Returns false immediately if lengths differ (length
// is not secret), else compares without short-circuiting. For hash compares.
bool constant_time_equals(std::string_view a, std::string_view b);

// Extract the token from an "Authorization: Bearer <token>" value. The scheme
// match is case-insensitive; surrounding whitespace is trimmed. Returns false
// if the header is empty, not a Bearer credential, or the token is empty.
bool parse_bearer(const std::string& authorization_header, std::string& token_out);

// Build a RealmGrant from a token row's `grants` JSON and the principal name.
// Shape: {"home":"nyx","read":["nyx","commons"],"write":[...],"max_sensitivity":"medium"}.
// read/write containing "*" sets read_all/write_all. Fails CLOSED: a missing or
// empty home, or a malformed shape, returns false with `err` set.
bool grant_from_json(const nlohmann::json& grants,
                     const std::string& principal,
                     RealmGrant& out,
                     std::string& err);

// Resolve a RealmGrant from the [[auth.principals]] config template by name.
// Returns nullopt if no principal of that name is configured.
std::optional<RealmGrant> grant_from_config(const AuthConfig& cfg,
                                            const std::string& principal);

// Map a verified JWT's claims to a principal name: reads the configured
// principal claim (default "sub"), then applies jwt_subject_map overrides
// (for issuers whose subjects are UUIDs rather than names). Returns nullopt
// when the claim is missing/empty — the caller must fail closed.
std::optional<std::string> resolve_jwt_principal(const AuthConfig& cfg,
                                                 const nlohmann::json& claims);

}  // namespace gptimage
