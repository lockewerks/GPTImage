#pragma once

#include <string>
#include <string_view>

// Password hashing for the OAuth login (principal_credentials.password_phc).
//
// KDF: scrypt via OpenSSL's EVP_KDF, ln=17 (N=2^17, ~128 MiB per derivation).
// Argon2id is the modern default and IS available on the deployment (OpenSSL
// 3.5.6); scrypt was originally chosen against a 3.0 floor that no longer
// binds. The PHC string carries the algorithm + params, so a later argon2id
// swap is schema-free — new hashes get an $argon2id$ prefix, old $scrypt$ rows
// keep verifying. Tracked as a follow-up.
//
// Produced format:  $scrypt$ln=17,r=8,p=1[,pep=v1]$<salt-b64>$<hash-b64>
// (PHC string; b64 is standard-alphabet base64 without padding.)
//
// Optional pepper: set GPTIMAGE_PASSWORD_PEPPER in the app host's environment
// and the password is HMAC-SHA256'd with it before scrypt, with the row tagged
// `pep=v1`. A credentials-table leak alone (the DB is on a separate host from
// the pepper) is then uncrackable. Backward compatible and opt-in: rows without
// the tag verify with no pepper; unset env ⇒ behavior unchanged.

namespace gptimage {

// Hash `password` with a fresh random 16-byte salt. Throws std::runtime_error
// on RNG or KDF failure (never returns a weak fallback).
std::string hash_password(std::string_view password);

// Verify `password` against a stored PHC string. Returns false on mismatch
// AND on any malformed/unsupported input — verification fails closed and
// never throws for bad data (a corrupt DB row must read as "wrong password",
// not take the login endpoint down).
bool verify_password(std::string_view password, std::string_view phc);

}  // namespace gptimage
