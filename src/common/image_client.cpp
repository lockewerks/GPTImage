#include <gptimage/image_client.hpp>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <utility>

namespace gptimage {

using nlohmann::json;

namespace {

std::string mime_for_format(const std::string& f) {
    if (f == "jpeg" || f == "jpg") return "image/jpeg";
    if (f == "webp")               return "image/webp";
    return "image/png";
}

// Pull a human-readable message out of an API error body, falling back to a
// truncated raw body so moderation/validation reasons still reach the caller.
std::string error_message(const cpr::Response& r) {
    try {
        auto j = json::parse(r.text);
        if (j.contains("error") && j["error"].is_object()) {
            const auto& e = j["error"];
            if (e.contains("message") && e["message"].is_string()) {
                std::string msg = e["message"].get<std::string>();
                if (e.contains("code") && e["code"].is_string()) {
                    msg += " [" + e["code"].get<std::string>() + "]";
                }
                return msg;
            }
        }
    } catch (...) {
        // fall through to the raw body
    }
    std::string body = r.text.substr(0, 300);
    return "status " + std::to_string(r.status_code) +
           (body.empty() ? "" : (": " + body));
}

ImageResponse parse_response(const cpr::Response& r, const std::string& mime) {
    json j;
    try {
        j = json::parse(r.text);
    } catch (...) {
        throw ImageError("malformed response from image API");
    }
    if (!j.contains("data") || !j["data"].is_array()) {
        throw ImageError("image API response missing data[]");
    }
    ImageResponse out;
    for (const auto& item : j["data"]) {
        if (item.contains("b64_json") && item["b64_json"].is_string()) {
            GeneratedImage g;
            g.b64  = item["b64_json"].get<std::string>();
            g.mime = mime;
            out.images.push_back(std::move(g));
        }
    }
    if (out.images.empty()) {
        throw ImageError("image API returned no image data");
    }
    if (j.contains("usage") && j["usage"].is_object()) {
        const auto& u = j["usage"];
        out.usage.input_tokens  = u.value("input_tokens",  static_cast<long>(-1));
        out.usage.output_tokens = u.value("output_tokens", static_cast<long>(-1));
        out.usage.total_tokens  = u.value("total_tokens",  static_cast<long>(-1));
    }
    return out;
}

}  // namespace

std::vector<unsigned char> base64_decode(const std::string& in) {
    // Accept a data: URI by starting after the "base64," marker if present.
    const auto marker = in.find("base64,");
    const std::string s = (marker != std::string::npos) ? in.substr(marker + 7) : in;

    auto sextet = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    std::vector<unsigned char> out;
    out.reserve(s.size() * 3 / 4);
    int buf = 0, bits = 0;
    for (unsigned char c : s) {
        if (c == '=' || std::isspace(c)) continue;
        const int d = sextet(c);
        if (d < 0) return {};  // invalid character => reject whole input
        buf = (buf << 6) | d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<unsigned char>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

ImageClient::ImageClient(ImageConfig cfg) : cfg_(std::move(cfg)) {}

ImageResponse ImageClient::generate(const ImageRequest& req) {
    if (cfg_.api_key.empty()) {
        throw ImageError("OPENAI_API_KEY not set (env " + cfg_.api_key_env + ")");
    }

    json body;
    body["model"]  = cfg_.model;
    body["prompt"] = req.prompt;
    body["n"]      = req.n;
    if (!req.size.empty())       body["size"]          = req.size;
    if (!req.quality.empty())    body["quality"]       = req.quality;
    if (!req.background.empty()) body["background"]     = req.background;
    if (!req.format.empty())     body["output_format"] = req.format;
    if (!cfg_.moderation.empty()) body["moderation"]   = cfg_.moderation;
    if (req.compression >= 0 && (req.format == "jpeg" || req.format == "webp")) {
        body["output_compression"] = req.compression;
    }
    const std::string payload = body.dump();
    const std::string mime = mime_for_format(req.format);

    int delay_ms = cfg_.backoff_initial_ms;
    for (int attempt = 0; attempt <= cfg_.max_retries; ++attempt) {
        cpr::Response r = cpr::Post(
            cpr::Url{cfg_.generations_endpoint},
            cpr::Header{
                {"Authorization", "Bearer " + cfg_.api_key},
                {"Content-Type",  "application/json"},
            },
            cpr::Body{payload},
            cpr::Timeout{cfg_.timeout_s * 1000});

        if (r.status_code == 200) return parse_response(r, mime);

        const bool retryable =
            r.status_code == 0 /* network */ ||
            r.status_code == 429 ||
            (r.status_code >= 500 && r.status_code < 600);
        if (!retryable || attempt == cfg_.max_retries) {
            throw ImageError(error_message(r));  // includes moderation/4xx reasons
        }

        int wait_ms = delay_ms;
        if (auto it = r.header.find("Retry-After"); it != r.header.end()) {
            try { wait_ms = std::max(wait_ms, std::stoi(it->second) * 1000); }
            catch (...) { /* malformed header */ }
        }
        spdlog::warn("image.generate: status {}, retrying in {}ms (attempt {}/{})",
                     r.status_code, wait_ms, attempt + 1, cfg_.max_retries);
        std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
        delay_ms = std::min(delay_ms * 2, 30000);
    }
    throw ImageError("image.generate: retry loop exited unexpectedly");
}

ImageResponse ImageClient::edit(const ImageRequest& req,
                                const std::vector<std::vector<unsigned char>>& images,
                                const std::optional<std::vector<unsigned char>>& mask) {
    if (cfg_.api_key.empty()) {
        throw ImageError("OPENAI_API_KEY not set (env " + cfg_.api_key_env + ")");
    }
    if (images.empty()) {
        throw ImageError("image edit requires at least one input image");
    }

    // The OpenAI SDK sends a single input under the "image" field and multiple
    // under "image[]"; match that so both shapes are accepted server-side.
    const std::string img_field = images.size() == 1 ? "image" : "image[]";

    cpr::Multipart mp{};
    mp.parts.emplace_back("model", cfg_.model);
    mp.parts.emplace_back("prompt", req.prompt);
    mp.parts.emplace_back("n", std::to_string(req.n));
    if (!req.size.empty())        mp.parts.emplace_back("size", req.size);
    if (!req.quality.empty())     mp.parts.emplace_back("quality", req.quality);
    if (!req.format.empty())      mp.parts.emplace_back("output_format", req.format);
    if (!cfg_.moderation.empty()) mp.parts.emplace_back("moderation", cfg_.moderation);
    for (size_t i = 0; i < images.size(); ++i) {
        mp.parts.emplace_back(cpr::Part(
            img_field,
            cpr::Buffer{images[i].begin(), images[i].end(), "image" + std::to_string(i) + ".png"},
            "image/png"));
    }
    if (mask) {
        mp.parts.emplace_back(cpr::Part(
            "mask",
            cpr::Buffer{mask->begin(), mask->end(), "mask.png"},
            "image/png"));
    }

    const std::string mime = mime_for_format(req.format);

    int delay_ms = cfg_.backoff_initial_ms;
    for (int attempt = 0; attempt <= cfg_.max_retries; ++attempt) {
        // No explicit Content-Type: cpr sets multipart/form-data + boundary.
        cpr::Response r = cpr::Post(
            cpr::Url{cfg_.edits_endpoint},
            cpr::Header{{"Authorization", "Bearer " + cfg_.api_key}},
            mp,
            cpr::Timeout{cfg_.timeout_s * 1000});

        if (r.status_code == 200) return parse_response(r, mime);

        const bool retryable =
            r.status_code == 0 ||
            r.status_code == 429 ||
            (r.status_code >= 500 && r.status_code < 600);
        if (!retryable || attempt == cfg_.max_retries) {
            throw ImageError(error_message(r));
        }

        int wait_ms = delay_ms;
        if (auto it = r.header.find("Retry-After"); it != r.header.end()) {
            try { wait_ms = std::max(wait_ms, std::stoi(it->second) * 1000); }
            catch (...) {}
        }
        spdlog::warn("image.edit: status {}, retrying in {}ms (attempt {}/{})",
                     r.status_code, wait_ms, attempt + 1, cfg_.max_retries);
        std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
        delay_ms = std::min(delay_ms * 2, 30000);
    }
    throw ImageError("image.edit: retry loop exited unexpectedly");
}

}  // namespace gptimage
