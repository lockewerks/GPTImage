# src/common — shared static library: config, DB wrapper, the OpenAI image
# client, the realm/grant model, and the JWT + password primitives the auth and
# OAuth layers build on. Linked by gptimage_mcp, gptimage_cli, and the tests.

find_package(PostgreSQL REQUIRED)

set(GPTIMAGE_COMMON_SOURCES
    config.cpp
    config_write.cpp
    db.cpp
    image_client.cpp
    realm.cpp
    auth.cpp
    jwt_verify.cpp
    jwt_sign.cpp
    password_hash.cpp
)

add_library(gptimage_common STATIC ${GPTIMAGE_COMMON_SOURCES})

# cpr is PUBLIC so the MCP tools link the same HTTP client the image backend
# uses. OpenSSL is PUBLIC — jwt_sign/jwt_verify and password_hash need it, and
# consumers inheriting gptimage_common get the symbols transitively.
target_link_libraries(gptimage_common
    PUBLIC
        gptimage_include
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        tomlplusplus::tomlplusplus
        cpr::cpr
        OpenSSL::SSL
        OpenSSL::Crypto
    PRIVATE
        PostgreSQL::PostgreSQL
)

set_target_properties(gptimage_common PROPERTIES
    LINKER_LANGUAGE CXX
)
