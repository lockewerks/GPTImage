#include "tool_common.hpp"

#include <chrono>
#include <string>

namespace gptimage {

using nlohmann::json;

// Fetch an image render started by gptimage_generate or gptimage_edit. Blocks up
// to job_poll_seconds for the job to finish, so a render that completes during
// the window returns immediately; otherwise it reports "pending" and the caller
// calls again with the same id. Read-only: it never starts new work.
json tool_result(const json& args, ToolContext& ctx) {
    const std::string id = args.value("job_id", std::string());
    if (id.empty()) {
        return text_result("job_id is required (the id returned by gptimage_generate "
                           "or gptimage_edit)", true);
    }
    auto snap = ctx.jobs.wait_for(
        id, std::chrono::seconds(ctx.cfg.image.job_poll_seconds));
    return render_job(snap, id, ctx.cfg.image.public_base_url);
}

}  // namespace gptimage
