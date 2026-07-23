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
        {"type", "string"}, {"enum", quality_enum}, {"default", "low"},
        {"description",
            "Rendering quality vs speed. Prefer \"low\" for interactive requests: "
            "it is fast (~15-30s) and cheap. \"medium\" is a balance. \"high\" is "
            "best but slow (~2 minutes for large sizes) and can exceed a remote "
            "connector's tool-call timeout, so only use it when the user explicitly "
            "asks for final/high quality and can wait. \"auto\" lets the model decide."},
    };
    const json format_prop = {
        {"type", "string"}, {"enum", format_enum}, {"default", "webp"},
        {"description",
            "Output image format. Defaults to webp: it is a fraction of a png's "
            "size, so the picture is light enough to render inline instead of "
            "being dropped for size. png is lossless but large; use it only when "
            "you need that and can accept a heavier payload."},
    };
    const json n_prop = {
        {"type", "integer"}, {"default", 1}, {"minimum", 1}, {"maximum", 4},
        {"description", "How many images to generate (capped by the server)."},
    };
    const json compression_prop = {
        {"type", "integer"}, {"minimum", 0}, {"maximum", 100},
        {"description",
            "Quality for the lossy formats webp/jpeg, 0-100 (higher is better and "
            "larger). Ignored for png. Defaults to the server setting, which keeps "
            "the picture light enough to render inline."},
    };

    return json::array({
        {
            {"name", "gptimage_generate"},
            {"description",
                "Generate an image from a text prompt with OpenAI gpt-image-2 "
                "(\"ChatGPT Images 2.0\"). Describe what you want in plain language; "
                "the model handles composition, style, and legible text. A fast "
                "render (the default low quality) returns the image inline right "
                "here. A slower one (medium/high, or a large size) instead returns "
                "a job_id with status \"pending\" — when that happens, call the "
                "gptimage_result tool with that job_id to fetch the finished image, "
                "and keep calling it until the image comes back. Use quality:\"low\" "
                "for quick drafts and quality:\"high\" for finished work (high can "
                "take 1-3 minutes and will come back via a job_id). When the result "
                "includes a markdown image link, show the picture to the user by "
                "putting that link in your reply verbatim; it renders inline."},
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
                    {"compression", compression_prop},
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
                "change. With a mask (base64 PNG whose transparent pixels mark the "
                "region to change) it does targeted inpainting; multiple inputs can "
                "be composited into one scene. Like gptimage_generate, a fast edit "
                "returns the image inline, while a slower one returns a job_id with "
                "status \"pending\" that you fetch with the gptimage_result tool. "
                "Use this to iterate on a previous result. When the result includes "
                "a markdown image link, show the picture to the user by putting that "
                "link in your reply verbatim; it renders inline."},
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
                    {"size",        size_prop},
                    {"quality",     quality_prop},
                    {"format",      format_prop},
                    {"n",           n_prop},
                    {"compression", compression_prop},
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
        {
            {"name", "gptimage_result"},
            {"description",
                "Fetch an image that gptimage_generate or gptimage_edit started but "
                "did not return inline (they handed back a job_id with status "
                "\"pending\"). Pass that job_id here. If the render is finished the "
                "image is returned inline; if it is still working this reports "
                "\"pending\" again, in which case call gptimage_result once more with "
                "the same job_id. High-quality renders take 1-3 minutes, so several "
                "polls are normal. This is the only way to retrieve a slow render. "
                "When the result includes a markdown image link, show the picture to "
                "the user by putting that link in your reply verbatim; it renders "
                "inline."},
            {"inputSchema", {
                {"type", "object"},
                {"properties", {
                    {"job_id", {{"type", "string"},
                                {"description", "The job_id returned by gptimage_generate or gptimage_edit."}}},
                }},
                {"required", json::array({"job_id"})},
            }},
            {"annotations", {
                {"title", "Get Image Result"},
                {"readOnlyHint", true},   // just fetches; never starts new work
                {"openWorldHint", false},
            }},
        },
    });
}

json mcp_tool_call(const std::string& name, const json& arguments, ToolContext& ctx) {
    if (name == "gptimage_generate") return tool_generate(arguments, ctx);
    if (name == "gptimage_edit")     return tool_edit(arguments, ctx);
    if (name == "gptimage_result")   return tool_result(arguments, ctx);
    return text_result("unknown tool: '" + name + "'", /*is_error=*/true);
}

}  // namespace gptimage
