#pragma once

#include <gptimage/config.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace gptimage {

// One image returned by the API. `b64` is the base64 payload exactly as the API
// produced it (data[i].b64_json) — the MCP image block wants base64, so it goes
// straight through with no decode/re-encode. `mime` is derived from the request
// format.
struct GeneratedImage {
    std::string b64;
    std::string mime;   // "image/png" | "image/jpeg" | "image/webp"
};

// Token usage as reported by the API, for cost accounting/logging. -1 = absent.
struct ImageUsage {
    long input_tokens  = -1;
    long output_tokens = -1;
    long total_tokens  = -1;
};

struct ImageResponse {
    std::vector<GeneratedImage> images;
    ImageUsage                  usage;
};

// Request parameters shared by generate and edit. Empty strings fall back to the
// ImageConfig defaults at the call site and are omitted from the wire request
// when still empty (letting the API's own default apply).
struct ImageRequest {
    std::string prompt;
    std::string size;        // WxH | "auto"
    std::string quality;     // auto|low|medium|high
    std::string background;  // transparent|opaque|auto  (generate only)
    std::string format;      // png|jpeg|webp
    int         n = 1;
    int         compression = -1;  // 0..100 for jpeg/webp; -1 => omit
};

// Any failure the tool surfaces to the caller as an isError result: a missing
// key, network/5xx/429 after retries, a 4xx (including moderation/policy
// rejections, which are never retried), or a malformed response. The message is
// the API's own error text when available.
struct ImageError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Standard-base64 decode (tolerates whitespace and a leading data: URI prefix).
// Returns an empty vector on invalid input. Used to turn the base64 image args
// of gptimage_edit back into the raw bytes the multipart upload needs.
std::vector<unsigned char> base64_decode(const std::string& in);

class ImageClient {
public:
    explicit ImageClient(ImageConfig cfg);

    // POST <generations_endpoint> as JSON.
    ImageResponse generate(const ImageRequest& req);

    // POST <edits_endpoint> as multipart/form-data. `images` are raw input bytes
    // (PNG/JPEG/WebP); `mask` is optional (raw bytes; its alpha channel marks
    // the region to edit).
    ImageResponse edit(const ImageRequest& req,
                       const std::vector<std::vector<unsigned char>>& images,
                       const std::optional<std::vector<unsigned char>>& mask);

private:
    ImageConfig cfg_;
};

}  // namespace gptimage
