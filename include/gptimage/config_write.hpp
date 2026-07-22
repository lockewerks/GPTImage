#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Config mutation for the tray settings UI. The tray edits a dozen scalar
// keys; everything else in gptimage.toml — comments (the operator's in-file
// notes), a hand-added [oracle] section, the whole [auth] block, keys a future
// version adds — must survive a write byte-for-byte. toml++ round-trips would
// flatten all of that, so we patch in place: find the `key = value` line inside
// its section and replace only the value, preserving every other byte.

namespace gptimage {

// Atomically replace `path`'s contents with `content`: write a sibling temp
// file, fsync-equivalent, then rename over the target (MoveFileEx replace on
// Windows). A reader never sees a half-written file. Throws on failure.
void atomic_write_text(const std::filesystem::path& path, std::string_view content);

// Set each `key = value` under [section] in the TOML at `path`, preserving all
// other lines, comments, and sections verbatim. `kv` values are pre-formatted
// TOML literals — "30000", "true", "\"C:/path\"", "[\"a\",\"b\"]" — the caller
// owns quoting/escaping. A key absent from the section is inserted; an absent
// section is appended. The file is parsed before AND after the edit; if either
// parse fails the original is left untouched and the function throws (never
// clobber a file we can't safely round-trip).
void patch_toml_keys(const std::filesystem::path& path,
                     std::string_view section,
                     const std::vector<std::pair<std::string, std::string>>& kv);

// Per-machine runtime state directory: %ProgramData%\GPTImage\state on
// Windows, else <temp>/gptimage-state. Created if absent (best effort).
// Holds the capture/ingest heartbeat JSONs and the capture-pause sentinel.
std::filesystem::path state_dir();

// TOML-quote a string value: wrap in double quotes, escape " and \. For
// building the `value` arguments to patch_toml_keys.
std::string toml_quote(std::string_view s);

}  // namespace gptimage
