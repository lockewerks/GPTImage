#pragma once

#include <nlohmann/json.hpp>

#include <gptimage/config.hpp>

#include <string>

namespace gptimage {

struct ToolContext;

// Schemas for tools/list. Each entry is {name, description, inputSchema,
// annotations}. annotations carries the MCP tool hints (title, readOnlyHint,
// destructiveHint, idempotentHint, openWorldHint) — read-only tools set
// readOnlyHint:true so write-gating clients (e.g. ChatGPT dev mode) don't
// gate them as writes.
nlohmann::json mcp_tool_schemas();

// Handle a tools/call. Returns the MCP tool-result shape:
//   { "content": [ {"type": "text", "text": "..."}, ... ], "isError": bool? }
nlohmann::json mcp_tool_call(const std::string& name,
                             const nlohmann::json& arguments,
                             ToolContext& ctx);

}  // namespace gptimage
