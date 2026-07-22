cmake_minimum_required(VERSION 3.25)
project(gptimage VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Single source of truth for the version: --version output, the Windows
# VERSIONINFO resource, and the installer name all read PROJECT_VERSION.
configure_file(
    "${CMAKE_SOURCE_DIR}/cmake/version.hpp.in"
    "${CMAKE_BINARY_DIR}/generated/gptimage/version.hpp"
    @ONLY)

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8)
    add_definitions(-DNOMINMAX -DWIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# ---------------------------------------------------------------------------
# PostgreSQL auto-detection (Windows): pick the newest install under the default
# PostgreSQL path unless PostgreSQL_ROOT is already set. On Linux find_package
# finds libpq via pkg-config without this.
# ---------------------------------------------------------------------------
if(WIN32 AND NOT DEFINED PostgreSQL_ROOT)
    file(GLOB _pg_candidates "C:/Program Files/PostgreSQL/*")
    if(_pg_candidates)
        list(SORT _pg_candidates)
        list(REVERSE _pg_candidates)
        list(GET _pg_candidates 0 PostgreSQL_ROOT)
        message(STATUS "Auto-detected PostgreSQL_ROOT: ${PostgreSQL_ROOT}")
    endif()
endif()
if(PostgreSQL_ROOT)
    set(PostgreSQL_INCLUDE_DIR "${PostgreSQL_ROOT}/include")
    set(PostgreSQL_LIBRARY_DIR "${PostgreSQL_ROOT}/lib")
endif()

# ---------------------------------------------------------------------------
# libpq runtime DLLs to ship next to each built exe so they run standalone
# without PostgreSQL's bin dir on PATH. Version suffixes are globbed so bumps
# of the installer don't strand us (e.g. libssl-3-x64 → libssl-4-x64).
# Populated on Windows only; on Linux libpq.so is resolved at runtime by the
# dynamic linker and there's nothing to copy.
# ---------------------------------------------------------------------------
if(WIN32 AND PostgreSQL_ROOT)
    file(GLOB GPTIMAGE_PG_RUNTIME_DLLS
        "${PostgreSQL_ROOT}/bin/libpq.dll"
        "${PostgreSQL_ROOT}/bin/libssl-*.dll"
        "${PostgreSQL_ROOT}/bin/libcrypto-*.dll"
        "${PostgreSQL_ROOT}/bin/libiconv-*.dll"
        "${PostgreSQL_ROOT}/bin/libintl-*.dll"
        "${PostgreSQL_ROOT}/bin/libwinpthread-*.dll"
    )
    message(STATUS "PostgreSQL runtime DLLs to bundle: ${GPTIMAGE_PG_RUNTIME_DLLS}")
endif()

# Copies the libpq + transitive runtime DLLs next to ${target}'s output exe
# after every build (copy_if_different, so unchanged sources are a no-op).
function(gptimage_copy_pg_runtime_dlls target)
    if(WIN32 AND GPTIMAGE_PG_RUNTIME_DLLS)
        foreach(_dll IN LISTS GPTIMAGE_PG_RUNTIME_DLLS)
            add_custom_command(TARGET ${target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_dll}" "$<TARGET_FILE_DIR:${target}>"
                VERBATIM)
        endforeach()
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(GPTIMAGE_BUILD_TESTS "Build unit and integration tests" ON)
option(GPTIMAGE_FETCH_DEPS  "Fetch third-party dependencies via FetchContent" ON)

# ---------------------------------------------------------------------------
# Third-party dependencies
# ---------------------------------------------------------------------------
if(GPTIMAGE_FETCH_DEPS)
    # CMake 4.x dropped support for scripts targeting CMake < 3.5. Several of
    # our FetchContent dependencies (notably doctest 2.4.11) still declare
    # `cmake_minimum_required(VERSION 3.0)`. This sets a compatibility floor
    # for all sub-projects. Remove once upstream deps catch up.
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

    include(FetchContent)

    FetchContent_Declare(json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    )
    FetchContent_Declare(spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.13.0
        GIT_SHALLOW TRUE
    )
    FetchContent_Declare(cpr
        GIT_REPOSITORY https://github.com/libcpr/cpr.git
        GIT_TAG 1.10.5
        GIT_SHALLOW TRUE
    )
    FetchContent_Declare(tomlplusplus
        GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
        GIT_TAG v3.4.0
        GIT_SHALLOW TRUE
    )
    FetchContent_Declare(doctest
        GIT_REPOSITORY https://github.com/doctest/doctest.git
        GIT_TAG v2.4.11
        GIT_SHALLOW TRUE
    )
    # cpp-httplib: header-only HTTP server for the MCP Streamable HTTP transport.
    # Plain HTTP only — Caddy terminates TLS in front of the loopback bind, so we
    # do NOT define CPPHTTPLIB_OPENSSL_SUPPORT (keeps OpenSSL out of this target).
    FetchContent_Declare(httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG v0.18.3
        GIT_SHALLOW TRUE
    )

    # Avoid cpr pulling its own curl; let it discover a system curl if present.
    # These settings are safe on fresh configures — if a dep disagrees it'll
    # overwrite with FORCE.
    set(CPR_USE_SYSTEM_CURL OFF CACHE BOOL "")
    set(BUILD_SHARED_LIBS   OFF CACHE BOOL "")
    # libpq is provided by the system Postgres install — find_package(PostgreSQL)
    # resolves it at src/common configure time.

    # OpenSSL is required for the embedded OAuth server's RS256 JWT signing and
    # verification (src/common/jwt_sign.cpp, jwt_verify.cpp) and for scrypt
    # password hashing (password_hash.cpp). PostgreSQL's Windows installer ships
    # matching libssl.lib + libcrypto.lib + headers under its install root, so by
    # default we point find_package(OpenSSL) at it. Override with
    # -DOPENSSL_ROOT_DIR=... for a different install (vcpkg, system package).
    if(WIN32 AND NOT DEFINED OPENSSL_ROOT_DIR AND PostgreSQL_ROOT)
        set(OPENSSL_ROOT_DIR "${PostgreSQL_ROOT}")
    endif()
    find_package(OpenSSL REQUIRED)
    message(STATUS "OpenSSL: ${OPENSSL_VERSION} (${OPENSSL_ROOT_DIR})")

    FetchContent_MakeAvailable(json spdlog cpr tomlplusplus doctest httplib)
endif()

# ---------------------------------------------------------------------------
# Common include path so src/* can #include <gptimage/foo.hpp>
# ---------------------------------------------------------------------------
add_library(gptimage_include INTERFACE)
target_include_directories(gptimage_include INTERFACE
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_BINARY_DIR}/generated"
)

# Attaches an icon + VERSIONINFO resource to a Windows exe. No-op elsewhere.
# assets/version.rc.in reads @PROJECT_VERSION_*@ and the per-target strings
# set just before configure_file.
function(gptimage_add_win_resources target description)
    if(WIN32)
        set(GPTIMAGE_RC_DESCRIPTION "${description}")
        set(GPTIMAGE_RC_INTERNALNAME "${target}")
        configure_file(
            "${CMAKE_SOURCE_DIR}/assets/version.rc.in"
            "${CMAKE_CURRENT_BINARY_DIR}/${target}_version.rc"
            @ONLY)
        target_sources(${target} PRIVATE
            "${CMAKE_CURRENT_BINARY_DIR}/${target}_version.rc")
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Subprojects
# ---------------------------------------------------------------------------
add_subdirectory(src/common)
add_subdirectory(src/mcp)
add_subdirectory(src/cli)

if(GPTIMAGE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
