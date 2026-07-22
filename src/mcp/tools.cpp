#include "tools.hpp"
#include "tool_common.hpp"

#include <string>

namespace gptimage {

using nlohmann::json;

json mcp_tool_schemas() {
    const json quality_enum = json::array({"auto", "low", "medium", "high"});
    const json format_enum  = json::array({"png", "jpeg", "webp"});

    const json size_prop = {
        {"type", "string"},
        {"description",
            "Output size as WIDTHxHEIGHT (each divisible by 16, aspect ratio "
            "between 1:3 and 3:1, up to 2K), or \"auto\" to let the model pick. "
            "Common: 1024x1024 (square), 1536x1024 (landscape), 1024x1536 "
            "(portrait). Defaults to the server setting."},
    };
    const json quality_prop = {
        {"type", "string"}, {"enum", quality_enum}, {"default", "high"},
        {"description",
            "Rendering quality. Higher costs more and is slower: low is a cheap "
            "draft, high is final art. \"auto\" lets the model decide."},
    };
    const json format_prop = {
        {"type", "string"}, {"enum", format_enum}, {"default", "png"},
        {"description",
            "Output image format. png is lossless; jpeg/webp are smaller (use "
            "with compression) which keeps the inline payload light."},
    };
    const json n_prop = {
        {"type", "integer"}, {"default", 1}, {"minimum", 1}, {"maximum", 4},
        {"description", "How many images to generate (capped by the server)."},
    };

    return json::array({
        {
            {"name", "gptimage_generate"},
            {"description",
                "Generate an image from a text prompt with OpenAI gpt-image-2 "
                "(\"ChatGPT Images 2.0\") and return it inline. Describe what you "
                "want in plain language; the model handles composition, style, "
                "and legible text. The image appears directly in the "
                "conversation. Use quality:\"low\" for quick drafts and "
                "quality:\"high\" for finished work."},
            {"inputSchema", {
                {"type", "object"},
                {"properties", {
                    {"prompt",      {{"type", "string"},
                                     {"description", "What to draw. Be specific about subject, style, mood, and any text to render."}}},
                    {"size",        size_prop},
                    {"quality",     quality_prop},
                    {"background",  {{"type", "string"},
                                     {"enum", json::array({"auto", "opaque", "transparent"})},
                                     {"default", "auto"},
                                     {"description", "Background handling. transparent needs png/webp and is not always honored by the model; auto is safest."}}},
                    {"format",      format_prop},
                    {"n",           n_prop},
                    {"compression", {{"type", "integer"}, {"minimum", 0}, {"maximum", 100},
                                     {"description", "Compression level 0-100 for jpeg/webp only. Ignored for png."}}},
                }},
                {"required", json::array({"prompt"})},
            }},
            {"annotations", {
                {"title", "Generate Image"},
                {"readOnlyHint", false},
                {"destructiveHint", false},
                {"idempotentHint", false},  // same prompt -> a different image each call
                {"openWorldHint", true},    // calls the OpenAI image API
            }},
        },
        {
            {"name", "gptimage_edit"},
            {"description",
                "Edit or combine existing images with gpt-image-2. Pass one or "
                "more input images as base64 strings plus a prompt describing the "
                "change; the model returns a new image inline. With a mask "
                "(base64 PNG whose transparent pixels mark the region to change) "
                "it does targeted inpainting. Multiple inputs can be composited "
                "into one scene. Use this to iterate on a previous result."},
            {"inputSchema", {
                {"type", "object"},
                {"properties", {
                    {"images", {{"type", "array"},
                                {"items", {{"type", "string"}}},
                                {"minItems", 1},
                                {"description", "Input image(s) as base64-encoded bytes (png/jpeg/webp)."}}},
                    {"prompt", {{"type", "string"},
                                {"description", "How to edit or combine the input image(s)."}}},
                    {"mask",   {{"type", "string"},
                                {"description", "Optional base64 PNG mask; transparent pixels mark the area to edit. Must match the first image's size."}}},
                    {"size",    size_prop},
                    {"quality", quality_prop},
                    {"format",  format_prop},
                    {"n",       n_prop},
                }},
                {"required", json::array({"images", "prompt"})},
            }},
            {"annotations", {
                {"title", "Edit Image"},
                {"readOnlyHint", false},
                {"destructiveHint", false},
                {"idempotentHint", false},
                {"openWorldHint", true},
            }},
        },
    });
}

json mcp_tool_call(const std::string& name, const json& arguments, ToolContext& ctx) {
    if (name == "gptimage_generate") return tool_generate(arguments, ctx);
    if (name == "gptimage_edit")     return tool_edit(arguments, ctx);
    return text_result("unknown tool: '" + name + "'", /*is_error=*/true);
}

}  // namespace gptimage
