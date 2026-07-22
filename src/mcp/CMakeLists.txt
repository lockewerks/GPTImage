# src/mcp — gptimage_mcp MCP server.
# Transport: stdio primary (Claude Desktop), Streamable HTTP secondary (the
# remote connector, fronted by Caddy). Tools are one file per handler.
#
# Split into a STATIC lib (server + dispatch + tools + auth + oauth) and a thin
# exe (main.cpp) so unit tests can link the handlers and the OAuth helpers
# directly. The exe is just the entry point + transport selection.

find_package(PostgreSQL REQUIRED)
find_package(Threads REQUIRED)  # job_store.cpp uses std::thread (pthread on Linux)

add_library(gptimage_mcp_lib STATIC
    server.cpp
    http_transport.cpp
    auth.cpp
    oauth.cpp
    oauth_http.cpp
    tools.cpp
    tool_common.cpp
    tool_generate.cpp
    tool_edit.cpp
    tool_result.cpp
    job_store.cpp
)

# PUBLIC include dir so test targets can #include "server.hpp" / "tool_common.hpp".
target_include_directories(gptimage_mcp_lib PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(gptimage_mcp_lib
    PUBLIC
        gptimage_common
        PostgreSQL::PostgreSQL
        Threads::Threads
    PRIVATE
        httplib::httplib
)

add_executable(gptimage_mcp main.cpp)
target_link_libraries(gptimage_mcp PRIVATE gptimage_mcp_lib)

gptimage_copy_pg_runtime_dlls(gptimage_mcp)
gptimage_add_win_resources(gptimage_mcp "GPTImage MCP Server")
