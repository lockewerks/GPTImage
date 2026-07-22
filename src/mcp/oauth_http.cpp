// HTTP surface of the embedded OAuth 2.1 authorization server: discovery
// documents, the login page, and the token/registration endpoints. Route
// handlers stay thin — every decision lives in OAuthService (oauth.cpp).
//
// CORS is a deliberate wildcard: authentication here is always an explicit
// bearer token or a submitted password, never a cookie, so there is no
// ambient credential for a cross-origin request to ride. (Caddy host-matches
// the public hostname before proxying, which retires the DNS-rebinding
// concern the MCP spec's Origin guidance targets.)

#include "oauth.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <spdlog/spdlog.h>

#include <string>
#include <variant>

namespace gptimage {

using nlohmann::json;

namespace {

void cors(httplib::Response& res) {
    res.set_header("Access-Control-Allow-Origin", "*");
}

void set_error(httplib::Response& res, const OAuthError& e) {
    res.status = e.http_status;
    res.set_header("Cache-Control", "no-store");
    cors(res);
    res.set_content(json{{"error", e.error}, {"error_description", e.description}}.dump(),
                    "application/json");
}

std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out.push_back(c);
        }
    }
    return out;
}

// The login page. Self-contained HTML (no external assets — the Caddy
// allowlist stays tight), form posts back to /oauth/authorize with the
// OAuth parameters riding as hidden fields. Everything echoed is escaped.
std::string render_login(const AuthorizeRequest& req, const std::string& error_msg) {
    std::string hidden;
    auto field = [&hidden](const char* name, const std::string& value) {
        if (value.empty()) return;
        hidden += "<input type=\"hidden\" name=\"" + std::string(name) +
                  "\" value=\"" + html_escape(value) + "\">\n";
    };
    field("response_type", "code");
    field("client_id", req.client_id);
    field("redirect_uri", req.redirect_uri);
    field("code_challenge", req.code_challenge);
    field("code_challenge_method", "S256");
    field("state", req.state);
    field("resource", req.resource);
    field("scope", req.scope);

    const std::string error_html =
        error_msg.empty() ? ""
                          : "<p class=\"err\">" + html_escape(error_msg) + "</p>\n";

    return
        "<!doctype html>\n"
        "<html><head><meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>GPTImage — sign in</title>\n"
        "<style>\n"
        "  :root { color-scheme: light dark; }\n"
        "  body { font: 16px/1.5 system-ui, sans-serif; display: grid;\n"
        "         place-items: center; min-height: 100vh; margin: 0;\n"
        "         background: Canvas; color: CanvasText; }\n"
        "  form { width: min(22rem, 90vw); padding: 2rem;\n"
        "         border: 1px solid color-mix(in srgb, CanvasText 20%, transparent);\n"
        "         border-radius: 12px; }\n"
        "  h1 { font-size: 1.2rem; margin: 0 0 .25rem; }\n"
        "  p.sub { margin: 0 0 1.25rem; opacity: .7; font-size: .9rem; }\n"
        "  label { display: block; font-size: .85rem; margin: .75rem 0 .25rem; }\n"
        "  input[type=text], input[type=password] {\n"
        "    width: 100%; box-sizing: border-box; padding: .55rem .7rem;\n"
        "    border: 1px solid color-mix(in srgb, CanvasText 30%, transparent);\n"
        "    border-radius: 8px; background: transparent; color: inherit; }\n"
        "  button { width: 100%; margin-top: 1.25rem; padding: .6rem;\n"
        "           border: 0; border-radius: 8px; font-weight: 600;\n"
        "           background: #6d5ae0; color: #fff; cursor: pointer; }\n"
        "  p.err { color: #d33; font-size: .9rem; margin: 0 0 .5rem; }\n"
        "</style></head><body>\n"
        "<form method=\"post\" action=\"/oauth/authorize\" autocomplete=\"off\">\n"
        "<h1>GPTImage</h1>\n"
        "<p class=\"sub\">Sign in to connect this assistant to your memory.</p>\n" +
        error_html + hidden +
        "<label for=\"principal\">Principal</label>\n"
        "<input type=\"text\" id=\"principal\" name=\"principal\" autofocus\n"
        "       autocapitalize=\"none\" autocorrect=\"off\" spellcheck=\"false\">\n"
        "<label for=\"password\">Password</label>\n"
        "<input type=\"password\" id=\"password\" name=\"password\">\n"
        "<button type=\"submit\">Sign in</button>\n"
        "</form></body></html>\n";
}

std::string error_page(const std::string& title, const std::string& detail) {
    return
        "<!doctype html>\n"
        "<html><head><meta charset=\"utf-8\"><title>GPTImage — error</title>\n"
        "<style>:root{color-scheme:light dark}"
        "body{font:16px/1.5 system-ui,sans-serif;display:grid;place-items:center;"
        "min-height:100vh;margin:0;background:Canvas;color:CanvasText}"
        "main{max-width:28rem;padding:2rem}h1{font-size:1.2rem}p{opacity:.8}</style>\n"
        "</head><body><main><h1>" + html_escape(title) + "</h1><p>" +
        html_escape(detail) + "</p></main></body></html>\n";
}

// Deliver an authorize-stage error per RFC 6749: redirect when the client's
// redirect_uri was verified, otherwise render a page and never redirect.
void authorize_error(httplib::Response& res,
                     const OAuthService::AuthorizeValidation& v) {
    if (v.redirect_error) {
        std::string url = v.req.redirect_uri;
        url += (url.find('?') == std::string::npos) ? '?' : '&';
        url += "error=" + v.error.error;
        if (!v.error.description.empty()) {
            url += "&error_description=" + httplib::detail::encode_url(v.error.description);
        }
        if (!v.req.state.empty()) {
            url += "&state=" + httplib::detail::encode_url(v.req.state);
        }
        res.set_redirect(url, 302);
        return;
    }
    res.status = v.error.http_status;
    res.set_content(error_page("Cannot continue", v.error.description), "text/html");
}

// The trustworthy client IP. httplib itself only ever sees 127.0.0.1 (Caddy on
// loopback), so we read X-Forwarded-For — but the LEFTMOST hop is
// client-controlled (Caddy appends the real peer to whatever the client sent),
// so we take the RIGHTMOST hop instead: the address Caddy itself observed. With
// exactly one trusted front proxy this is the real client, and it holds whether
// Caddy overwrites XFF (deploy snippet) or merely appends. Trim surrounding
// whitespace. Falls back to the socket peer when XFF is absent.
std::string client_ip(const httplib::Request& req) {
    const std::string xff = req.get_header_value("X-Forwarded-For");
    if (!xff.empty()) {
        const size_t comma = xff.rfind(',');
        std::string hop = (comma == std::string::npos) ? xff : xff.substr(comma + 1);
        const size_t b = hop.find_first_not_of(" \t");
        const size_t e = hop.find_last_not_of(" \t");
        if (b != std::string::npos) return hop.substr(b, e - b + 1);
    }
    return req.remote_addr;
}

}  // namespace

void register_oauth_routes(httplib::Server& svr, OAuthService& oauth, const Config& cfg) {
    (void)cfg;

    // ---- discovery ----------------------------------------------------------
    auto serve_doc = [](httplib::Response& res, const json& doc) {
        cors(res);
        res.set_header("Cache-Control", "public, max-age=3600");
        res.set_content(doc.dump(2), "application/json");
    };
    svr.Get("/.well-known/oauth-protected-resource",
            [&oauth, serve_doc](const httplib::Request&, httplib::Response& res) {
                serve_doc(res, oauth.metadata_protected_resource());
            });
    svr.Get("/.well-known/oauth-protected-resource/mcp",
            [&oauth, serve_doc](const httplib::Request&, httplib::Response& res) {
                serve_doc(res, oauth.metadata_protected_resource());
            });
    svr.Get("/.well-known/oauth-authorization-server",
            [&oauth, serve_doc](const httplib::Request&, httplib::Response& res) {
                serve_doc(res, oauth.metadata_authorization_server());
            });
    // Some clients (ChatGPT among them) probe the OIDC well-known first. Same
    // document — we make no OIDC claims beyond what RFC 8414 shares.
    svr.Get("/.well-known/openid-configuration",
            [&oauth, serve_doc](const httplib::Request&, httplib::Response& res) {
                serve_doc(res, oauth.metadata_authorization_server());
            });
    svr.Get("/.well-known/jwks.json",
            [&oauth, serve_doc](const httplib::Request&, httplib::Response& res) {
                serve_doc(res, oauth.jwks());
            });

    // ---- authorize ----------------------------------------------------------
    svr.Get("/oauth/authorize", [&oauth](const httplib::Request& req, httplib::Response& res) {
        auto v = oauth.validate_authorize(req.params);
        if (!v.ok) {
            authorize_error(res, v);
            return;
        }
        res.set_header("Cache-Control", "no-store");
        res.set_content(render_login(v.req, ""), "text/html");
    });

    svr.Post("/oauth/authorize", [&oauth](const httplib::Request& req, httplib::Response& res) {
        // Hidden fields are untrusted: re-validate everything as if this were
        // a fresh authorize request.
        auto v = oauth.validate_authorize(req.params);
        if (!v.ok) {
            authorize_error(res, v);
            return;
        }
        const std::string principal = req.get_param_value("principal");
        std::string password        = req.get_param_value("password");
        // Bound the field independent of the 1 MiB body cap; scrypt cost is
        // length-insensitive so this is only about not copying absurd inputs.
        if (password.size() > 1024) password.clear();

        auto outcome = oauth.handle_login(v.req, principal, password, client_ip(req));
        // Scrub our copy of the plaintext once the login has been evaluated.
        if (!password.empty()) OPENSSL_cleanse(password.data(), password.size());
        if (std::holds_alternative<std::string>(outcome)) {
            res.set_header("Cache-Control", "no-store");
            res.set_redirect(std::get<std::string>(outcome), 302);
            return;
        }
        const OAuthError& e = std::get<OAuthError>(outcome);
        if (e.http_status == 401) {
            // Re-render the form with the error. The 401 status is load-
            // bearing: the fail2ban jail counts these.
            res.status = 401;
            res.set_header("Cache-Control", "no-store");
            res.set_content(render_login(v.req, e.description), "text/html");
            return;
        }
        res.status = e.http_status;
        res.set_content(error_page("Cannot continue", e.description), "text/html");
    });

    // ---- token + registration ------------------------------------------------
    svr.Post("/oauth/token", [&oauth](const httplib::Request& req, httplib::Response& res) {
        auto outcome = oauth.token(req.params, req.get_header_value("Authorization"));
        if (std::holds_alternative<OAuthError>(outcome)) {
            set_error(res, std::get<OAuthError>(outcome));
            return;
        }
        cors(res);
        res.set_header("Cache-Control", "no-store");
        res.set_header("Pragma", "no-cache");
        res.set_content(std::get<json>(outcome).dump(), "application/json");
    });

    svr.Post("/oauth/register", [&oauth](const httplib::Request& req, httplib::Response& res) {
        if (!json_within_depth(req.body, 64)) {
            set_error(res, OAuthError{400, "invalid_client_metadata", "body too deeply nested"});
            return;
        }
        const json body = json::parse(req.body, nullptr, /*allow_exceptions=*/false);
        if (body.is_discarded()) {
            spdlog::warn("oauth: /oauth/register rejected: body not JSON (len={})", req.body.size());
            set_error(res, OAuthError{400, "invalid_client_metadata", "body must be JSON"});
            return;
        }
        auto outcome = oauth.register_client(body, client_ip(req));
        if (std::holds_alternative<OAuthError>(outcome)) {
            const OAuthError& e = std::get<OAuthError>(outcome);
            // Log the offending body (truncated) + reason so a connector whose
            // DCR shape we didn't anticipate is diagnosable without guesswork.
            std::string dumped = body.dump();
            if (dumped.size() > 512) dumped = dumped.substr(0, 512) + "...";
            spdlog::warn("oauth: /oauth/register {} ({}) body={}",
                         e.error, e.description, dumped);
            set_error(res, e);
            return;
        }
        cors(res);
        res.status = 201;
        res.set_header("Cache-Control", "no-store");
        res.set_content(std::get<json>(outcome).dump(), "application/json");
    });

    // ---- CORS preflight -------------------------------------------------------
    static const char* kPreflightPaths[] = {
        "/mcp", "/oauth/token", "/oauth/register",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
    };
    for (const char* path : kPreflightPaths) {
        svr.Options(path, [](const httplib::Request&, httplib::Response& res) {
            res.status = 204;
            cors(res);
            res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            res.set_header("Access-Control-Allow-Headers",
                           "Authorization, Content-Type, MCP-Protocol-Version");
            res.set_header("Access-Control-Expose-Headers", "WWW-Authenticate");
            res.set_header("Access-Control-Max-Age", "86400");
        });
    }
}

}  // namespace gptimage
