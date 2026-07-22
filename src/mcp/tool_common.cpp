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

}  // namespace gptimage
