#include "tool_common.hpp"

#include <gptimage/image_client.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <string>
#include <utility>

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

    // Start the render on a background thread. The lambda is fully self-contained
    // (owns copies of the config and request), so it outlives this call safely.
    const std::string id = ctx.jobs.submit(
        "generate", ctx.grant.principal,
        [ic, req]() -> JobOutput {
            ImageClient client(ic);
            ImageResponse resp = client.generate(req);
            std::string caption = "Generated " + std::to_string(resp.images.size()) +
                (resp.images.size() == 1 ? " image" : " images") +
                " with " + ic.model + " (" + req.quality + ", " + req.size + ").";
            if (resp.usage.total_tokens >= 0) {
                caption += " Tokens: " + std::to_string(resp.usage.total_tokens) + ".";
            }
            return JobOutput{std::move(resp.images), std::move(caption)};
        });

    spdlog::info("gptimage_generate job={} principal={} quality={} size={}",
                 id, ctx.grant.principal, req.quality, req.size);

    // Give a fast render (low quality / small size) the chance to land inside
    // this one call; otherwise the caller polls gptimage_result with the id.
    auto snap = ctx.jobs.wait_for(id, std::chrono::seconds(ic.job_poll_seconds));
    return render_job(snap, id);
}

}  // namespace gptimage
