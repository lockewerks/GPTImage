#pragma once

#include <nlohmann/json.hpp>

#include <gptimage/config.hpp>
#include <gptimage/image_client.hpp>
#include <gptimage/realm.hpp>

#include "job_store.hpp"

#include <optional>
#include <string>
#include <vector>

namespace gptimage {

// Per-call context for MCP tool invocations. The image tools need the config
// (for [image] settings + the resolved API key), the caller's grant (for the
// principal in log lines), and the shared async job store (renders run on
// background threads so no single tool call outlives a connector's timeout).
struct ToolContext {
    const Config&     cfg;
    const RealmGrant& grant;
    JobStore&         jobs;
};

// Per-tool entry points (one .cpp each). generate/edit start a render and return
// the image if it lands within the poll window, else a job_id; result fetches a
// job_id.
nlohmann::json tool_generate(const nlohmann::json& args, ToolContext& ctx);
nlohmann::json tool_edit(const nlohmann::json& args, ToolContext& ctx);
nlohmann::json tool_result(const nlohmann::json& args, ToolContext& ctx);

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

// Turn a job snapshot into an MCP result: Done -> inline image(s); Error -> an
// error text result; Pending -> a machine-readable "still rendering, call
// gptimage_result again" result; nullopt (unknown/expired id) -> an error.
// Shared by generate, edit, and result so the three stay in lockstep.
//
// When public_base_url is non-empty a Done result also carries a text block with
// a markdown image link (<base>/i/<job_id>-<index>.<ext>) telling the client to
// render the picture in the conversation body, not just inside the collapsed
// tool-call block. Empty ⇒ inline base64 only.
nlohmann::json render_job(const std::optional<ImageJob>& snap, const std::string& id,
                          const std::string& public_base_url);

}  // namespace gptimage
