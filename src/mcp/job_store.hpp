#pragma once

#include <gptimage/image_client.hpp>

#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace gptimage {

// The finished product of a render: the images plus the human-readable caption
// the tool would have returned synchronously.
struct JobOutput {
    std::vector<GeneratedImage> images;
    std::string                 caption;
};

// The work a job runs on its background thread. Throwing marks the job Error
// with the exception's message.
using JobWork = std::function<JobOutput()>;

struct ImageJob {
    enum class Status { Pending, Done, Error };
    std::string id;
    std::string kind;         // "generate" | "edit"
    std::string principal;
    Status      status = Status::Pending;
    std::vector<GeneratedImage> images;   // valid when Done
    std::string caption;                  // valid when Done
    std::string error;                    // valid when Error
    std::chrono::steady_clock::time_point created;
};

// Thread-safe async registry for image renders. submit() runs the work on a
// detached background thread and returns a job id immediately; wait_for() blocks
// up to a bounded window for the job to leave Pending, so a fast render is
// delivered on the first poll and a slow one is fetched in safe, sub-timeout
// chunks. Finished jobs are retained for `ttl_seconds` so the result tool can
// pick them up, then evicted.
class JobStore {
public:
    explicit JobStore(int ttl_seconds = 900, int max_concurrent = 4);

    // Start `work`; returns the new job id. If the concurrency cap is already
    // reached the job is created already-Errored (no thread is spawned), so the
    // caller still gets an id whose result explains the rejection.
    std::string submit(const std::string& kind,
                       const std::string& principal,
                       JobWork work);

    // Wait up to `wait` for job `id` to leave Pending. Returns a snapshot copy,
    // or std::nullopt if the id is unknown or already evicted.
    std::optional<ImageJob> wait_for(const std::string& id,
                                     std::chrono::milliseconds wait);

private:
    void evict_locked();  // drop expired finished jobs; caller holds mtx_

    std::mutex              mtx_;
    std::condition_variable cv_;
    std::unordered_map<std::string, std::shared_ptr<ImageJob>> jobs_;
    std::chrono::seconds    ttl_;
    int                     max_concurrent_;
    int                     active_ = 0;
};

}  // namespace gptimage
