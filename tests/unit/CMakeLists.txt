# tests/unit — one executable per test file. Each is registered with ctest so
# `ctest --output-on-failure` works out of the box.

set(GPTIMAGE_UNIT_TESTS
    test_auth
    test_config
    test_config_write
    test_jwt_sign
    test_password_hash
    test_realm_grants
)

foreach(T IN LISTS GPTIMAGE_UNIT_TESTS)
    add_executable(${T} ${T}.cpp)
    target_link_libraries(${T} PRIVATE gptimage_common doctest::doctest)
    add_test(NAME ${T} COMMAND ${T})
endforeach()

# test_oauth exercises the AS's pure helpers (PKCE, redirect-host policy), and
# test_job_store the async render cache + hosted-URL result shaping — both live
# in gptimage_mcp_lib rather than gptimage_common.
add_executable(test_oauth test_oauth.cpp)
target_link_libraries(test_oauth PRIVATE gptimage_mcp_lib doctest::doctest)
add_test(NAME test_oauth COMMAND test_oauth)

add_executable(test_job_store test_job_store.cpp)
target_link_libraries(test_job_store PRIVATE gptimage_mcp_lib doctest::doctest)
add_test(NAME test_job_store COMMAND test_job_store)
