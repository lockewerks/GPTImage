#pragma once

#include <nlohmann/json.hpp>

#include <gptimage/config.hpp>
#include <gptimage/image_client.hpp>
#include <gptimage/realm.hpp>

#include <string>
#include <vector>

namespace gptimage {

// Per-call context for MCP tool invocations. The image tools are stateless: they
// need the config (for [image] settings + the resolved API key) and the caller's
// grant (for the principal in log lines). No DB or embedder — generation talks
// only to OpenAI.
struct ToolContext {
    const Config&     cfg;
    const RealmGrant& grant;
};

// Per-tool entry points (one .cpp each).
nlohmann::json tool_generate(const nlohmann::json& args, ToolContext& ctx);
nlohmann::json tool_edit(const nlohmann::json& args, ToolContext& ctx);

// ---------------------------------------------------------------------------
// Shared result helpers
// ---------------------------------------------------------------------------

// Wrap a plain string as an MCP tool result. Set is_error for a failure the
// model should see and react to (bad args, policy rejection, upstream failure).
nlohmann::json text_result(const std::string& text, bool is_error = false);

// Wrap arbitrary JSON as an MCP tool result (stringified into a text block).
nlohmann::json json_result(const nlohmann::json& data);

// Build an MCP result carrying one or more inline image blocks
// ({type:"image", data:<base64>, mimeType:...}) plus a trailing text caption.
// This is what puts the picture directly in the Claude conversation.
nlohmann::json image_result(const std::vector<GeneratedImage>& images,
                            const std::string& caption);

}  // namespace gptimage
