#pragma once

#include <gptimage/config.hpp>
#include <gptimage/db.hpp>
#include <gptimage/jwt_verify.hpp>
#include <gptimage/realm.hpp>

#include <string>

namespace gptimage {

// Outcome of authenticating one HTTP request. On success, `grant` carries the
// caller's realm authority. On failure, `error` is a short reason for logs —
// it is never returned to the client and never contains token material.
struct AuthResult {
    bool        ok = false;
    RealmGrant  grant;
    std::string error;
};

// Authenticate an Authorization header. Two credential shapes, dispatched by
// the token itself:
//   "gpt_..."          static bearer — SHA-256 lookup in gptimage.api_tokens
//   "xxx.yyy.zzz"      OAuth access JWT — verified by `jwt` (RS256, iss/aud/exp),
//                      subject mapped to a principal, grant resolved from
//                      [[auth.principals]]. `jwt == nullptr` means JWT auth is
//                      not configured on this server; JWTs then fail closed.
// Anything else fails. The HTTP layer maps any failure to 401.
AuthResult authenticate(const std::string& authorization_header,
                        DbConn& db,
                        const Config& cfg,
                        JwtVerifier* jwt);

}  // namespace gptimage
