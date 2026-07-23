#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "job_store.hpp"
#include "tool_common.hpp"

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

using namespace std::chrono_literals;

namespace {

// A trivial render: one tiny webp "image" and a caption, returned synchronously.
gptimage::JobOutput one_webp() {
    return gptimage::JobOutput{{{"QUJD", "image/webp"}}, "Generated 1 image."};
}

}  // namespace

TEST_CASE("JobStore serves a finished image and rejects bad lookups") {
    gptimage::JobStore store(900, 4);
    const std::string id = store.submit("generate", "tester", [] { return one_webp(); });

    auto snap = store.wait_for(id, 2s);
    REQUIRE(snap.has_value());
    CHECK(snap->status == gptimage::ImageJob::Status::Done);

    // This accessor is what the /i/ HTTP route serves from.
    auto img = store.get_image(id, 0);
    REQUIRE(img.has_value());
    CHECK(img->b64  == "QUJD");
    CHECK(img->mime == "image/webp");

    CHECK_FALSE(store.get_image(id, 1).has_value());            // index out of range
    CHECK_FALSE(store.get_image("job_missing", 0).has_value()); // unknown id
}

TEST_CASE("JobStore marks a throwing render as Error and serves no image") {
    gptimage::JobStore store(900, 4);
    const std::string id = store.submit(
        "generate", "tester",
        []() -> gptimage::JobOutput { throw std::runtime_error("boom"); });

    auto snap = store.wait_for(id, 2s);
    REQUIRE(snap.has_value());
    CHECK(snap->status == gptimage::ImageJob::Status::Error);
    CHECK(snap->error  == "boom");
    CHECK_FALSE(store.get_image(id, 0).has_value());
}

TEST_CASE("JobStore evicts a finished render after its TTL") {
    gptimage::JobStore store(1, 4);  // 1-second retention window
    const std::string id = store.submit("generate", "tester", [] { return one_webp(); });
    REQUIRE(store.wait_for(id, 2s).has_value());
    CHECK(store.get_image(id, 0).has_value());

    std::this_thread::sleep_for(1200ms);
    CHECK_FALSE(store.get_image(id, 0).has_value());  // dropped; nothing is persisted
}

TEST_CASE("render_job embeds a hosted markdown link only when a base URL is set") {
    gptimage::ImageJob job;
    job.id      = "job_deadbeef";
    job.status  = gptimage::ImageJob::Status::Done;
    job.caption = "Generated 1 image.";
    job.images.push_back({"QUJD", "image/webp"});

    SUBCASE("hosted: inline block plus a markdown link for the chat body") {
        auto res = gptimage::render_job(job, "job_deadbeef", "https://h.example");
        const auto& content = res.at("content");
        REQUIRE(content.is_array());
        CHECK(content[0].at("type").get<std::string>() == "image");      // fallback block
        CHECK(content[0].at("mimeType").get<std::string>() == "image/webp");

        bool found_link = false;
        for (const auto& c : content) {
            if (c.at("type").get<std::string>() == "text" &&
                c.at("text").get<std::string>().find(
                    "https://h.example/i/job_deadbeef-0.webp") != std::string::npos) {
                found_link = true;
            }
        }
        CHECK(found_link);
    }

    SUBCASE("local/stdio: no base URL, so no hosted link") {
        auto res = gptimage::render_job(job, "job_deadbeef", "");
        for (const auto& c : res.at("content")) {
            if (c.at("type").get<std::string>() == "text") {
                CHECK(c.at("text").get<std::string>().find("/i/") == std::string::npos);
            }
        }
    }
}

TEST_CASE("render_job reports pending and unknown jobs") {
    SUBCASE("unknown id is an error result naming the id") {
        auto res = gptimage::render_job(std::nullopt, "job_gone", "https://h.example");
        CHECK(res.value("isError", false) == true);
        CHECK(res.at("content")[0].at("text").get<std::string>().find("job_gone") !=
              std::string::npos);
    }
    SUBCASE("pending id tells the caller to poll gptimage_result again") {
        gptimage::ImageJob job;
        job.status = gptimage::ImageJob::Status::Pending;
        auto res = gptimage::render_job(job, "job_wait", "");
        const std::string text = res.at("content")[0].at("text").get<std::string>();
        CHECK(text.find("pending") != std::string::npos);
        CHECK(text.find("job_wait") != std::string::npos);
    }
}
