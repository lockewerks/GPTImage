#include "tool_common.hpp"

namespace gptimage {

using nlohmann::json;

json text_result(const std::string& text, bool is_error) {
    json out{
        {"content", json::array({
            json::object({{"type", "text"}, {"text", text}}),
        })},
    };
    if (is_error) out["isError"] = true;
    return out;
}

json json_result(const json& data) {
    return {
        {"content", json::array({
            json::object({{"type", "text"}, {"text", data.dump(2)}}),
        })},
    };
}

json image_result(const std::vector<GeneratedImage>& images, const std::string& caption) {
    json content = json::array();
    for (const auto& im : images) {
        content.push_back(json::object({
            {"type", "image"},
            {"data", im.b64},
            {"mimeType", im.mime},
        }));
    }
    if (!caption.empty()) {
        content.push_back(json::object({{"type", "text"}, {"text", caption}}));
    }
    return {{"content", content}};
}

json render_job(const std::optional<ImageJob>& snap, const std::string& id) {
    if (!snap) {
        return text_result(
            "No image job with id '" + id + "' (it may have finished long ago and "
            "expired, or the server restarted). Start a new generation.", true);
    }
    switch (snap->status) {
        case ImageJob::Status::Done:
            return image_result(snap->images, snap->caption);
        case ImageJob::Status::Error:
            return text_result("image job failed: " + snap->error, true);
        case ImageJob::Status::Pending:
        default:
            return json_result({
                {"status", "pending"},
                {"job_id", id},
                {"instructions",
                    "The image is still rendering (high quality can take 1-3 minutes). "
                    "Call the gptimage_result tool again with this exact job_id to fetch "
                    "it; keep calling until it returns the image."},
            });
    }
}

}  // namespace gptimage
