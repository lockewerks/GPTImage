# src/cli — gptimage_cli admin tool.
#
# Commands: migrate (applies numbered SQL in sql/migrations/), tokens (mint and
# manage static gpt_ bearer tokens), passwd (set an OAuth login password), and
# oauth (manage the embedded authorization server's signing key + clients).

find_package(PostgreSQL REQUIRED)

add_executable(gptimage_cli
    main.cpp
    cmd_migrate.cpp
    cmd_tokens.cpp
    cmd_passwd.cpp
    cmd_oauth.cpp
)

target_link_libraries(gptimage_cli
    PRIVATE
        gptimage_common
        PostgreSQL::PostgreSQL
)

gptimage_copy_pg_runtime_dlls(gptimage_cli)
gptimage_add_win_resources(gptimage_cli "GPTImage CLI")
