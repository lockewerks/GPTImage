#include "tool_common.hpp"

#include <gptimage/image_client.hpp>
#include <spdlog/spdlog.h>

#include <string>

namespace gptimage {

using nlohmann::json;

json tool_generate(const json& args, ToolContext& ctx) {
    const ImageConfig& ic = ctx.cfg.image;
    if (ic.api_key.empty()) {
        return text_result(
            "image generation is unavailable: the server has no OPENAI_API_KEY set", true);
    }

    const std::string prompt = args.value("prompt", std::string());
    if (prompt.empty()) {
        return text_result("prompt is required", true);
    }

    ImageRequest req;
    req.prompt      = prompt;
    req.size        = args.value("size",       ic.default_size);
    req.quality     = args.value("quality",    ic.default_quality);
    req.background  = args.value("background",  ic.default_background);
    req.format      = args.value("format",     ic.default_format);
    req.n           = args.value("n",           1);
    req.compression = args.value("compression", -1);
    if (req.n < 1) req.n = 1;
    if (req.n > ic.max_n) req.n = ic.max_n;

    try {
        ImageClient client(ic);
        const ImageResponse resp = client.generate(req);

        std::string caption = "Generated " + std::to_string(resp.images.size()) +
            (resp.images.size() == 1 ? " image" : " images") +
            " with " + ic.model + " (" + req.quality + ", " + req.size + ").";
        if (resp.usage.total_tokens >= 0) {
            caption += " Tokens: " + std::to_string(resp.usage.total_tokens) + ".";
        }
        spdlog::info("gptimage_generate principal={} n={} quality={} size={}",
                     ctx.grant.principal, resp.images.size(), req.quality, req.size);
        return image_result(resp.images, caption);
    } catch (const ImageError& e) {
        spdlog::warn("gptimage_generate failed: {}", e.what());
        return text_result(std::string("image generation failed: ") + e.what(), true);
    } catch (const std::exception& e) {
        spdlog::error("gptimage_generate error: {}", e.what());
        return text_result(std::string("image generation error: ") + e.what(), true);
    }
}

}  // namespace gptimage
