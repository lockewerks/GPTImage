#include "job_store.hpp"

#include <openssl/rand.h>
#include <spdlog/spdlog.h>

#include <thread>
#include <utility>

namespace gptimage {

namespace {

std::string random_job_id() {
    unsigned char b[12];
    if (RAND_bytes(b, sizeof(b)) != 1) {
        // Non-cryptographic fallback; ids only need to be unguessable-enough on
        // a single-tenant server, and RAND_bytes effectively never fails here.
        const auto n = std::chrono::steady_clock::now().time_since_epoch().count();
        for (size_t i = 0; i < sizeof(b); ++i) b[i] = static_cast<unsigned char>(n >> (i * 8));
    }
    static const char* hex = "0123456789abcdef";
    std::string s = "job_";
    for (unsigned char c : b) { s += hex[c >> 4]; s += hex[c & 0x0F]; }
    return s;
}

}  // namespace

JobStore::JobStore(int ttl_seconds, int max_concurrent)
    : ttl_(ttl_seconds > 0 ? ttl_seconds : 900),
      max_concurrent_(max_concurrent > 0 ? max_concurrent : 4) {}

void JobStore::evict_locked() {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = jobs_.begin(); it != jobs_.end();) {
        if (it->second->status != ImageJob::Status::Pending &&
            now - it->second->created > ttl_) {
            it = jobs_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string JobStore::submit(const std::string& kind, const std::string& principal,
                             JobWork work) {
    auto job = std::make_shared<ImageJob>();
    {
        std::lock_guard<std::mutex> lk(mtx_);
        evict_locked();
        job->id        = random_job_id();
        job->kind      = kind;
        job->principal = principal;
        job->created   = std::chrono::steady_clock::now();
        jobs_[job->id] = job;

        if (active_ >= max_concurrent_) {
            job->status = ImageJob::Status::Error;
            job->error  = "server is busy (too many concurrent renders); try again shortly";
            spdlog::warn("job {} rejected: concurrency cap {} reached", job->id, max_concurrent_);
            return job->id;
        }
        ++active_;
    }

    try {
        std::thread([this, job, work = std::move(work)]() mutable {
            JobOutput out;
            std::string err;
            try {
                out = work();
            } catch (const std::exception& e) {
                err = e.what();
            } catch (...) {
                err = "unknown error";
            }
            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (err.empty()) {
                    job->status  = ImageJob::Status::Done;
                    job->images  = std::move(out.images);
                    job->caption = std::move(out.caption);
                    spdlog::info("job {} done ({} image(s))", job->id, job->images.size());
                } else {
                    job->status = ImageJob::Status::Error;
                    job->error  = err;
                    spdlog::warn("job {} failed: {}", job->id, err);
                }
                --active_;
            }
            cv_.notify_all();
        }).detach();
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lk(mtx_);
        job->status = ImageJob::Status::Error;
        job->error  = std::string("could not start render thread: ") + e.what();
        --active_;
        cv_.notify_all();
    }

    return job->id;
}

std::optional<ImageJob> JobStore::wait_for(const std::string& id,
                                           std::chrono::milliseconds wait) {
    std::unique_lock<std::mutex> lk(mtx_);
    evict_locked();
    auto it = jobs_.find(id);
    if (it == jobs_.end()) return std::nullopt;
    auto job = it->second;  // shared_ptr keeps it alive across the wait
    if (job->status == ImageJob::Status::Pending) {
        cv_.wait_for(lk, wait, [&] { return job->status != ImageJob::Status::Pending; });
    }
    return *job;  // snapshot copy
}

std::optional<GeneratedImage> JobStore::get_image(const std::string& id, size_t index) {
    std::lock_guard<std::mutex> lk(mtx_);
    evict_locked();
    auto it = jobs_.find(id);
    if (it == jobs_.end()) return std::nullopt;
    const auto& job = *it->second;
    if (job.status != ImageJob::Status::Done || index >= job.images.size()) {
        return std::nullopt;
    }
    return job.images[index];  // copy of {b64, mime}
}

}  // namespace gptimage
