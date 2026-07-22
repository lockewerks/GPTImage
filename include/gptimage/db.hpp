#pragma once

#include <memory>
#include <string>

#include <gptimage/config.hpp>

// Forward declare libpq's PGconn so this header doesn't drag libpq-fe.h into
// every translation unit.
struct pg_conn;
typedef struct pg_conn PGconn;

namespace gptimage {

// RAII wrapper around libpq's PGconn. v1 uses single-connection semantics —
// a real pool lands when the daemon needs concurrency.
// The migrate runner and CLI commands operate on one connection at a time.
class DbConn {
public:
    explicit DbConn(const DatabaseConfig& cfg);
    ~DbConn();

    DbConn(const DbConn&)            = delete;
    DbConn& operator=(const DbConn&) = delete;
    DbConn(DbConn&&) noexcept;
    DbConn& operator=(DbConn&&) noexcept;

    // Native libpq handle for consumers that need direct access (exec, notify,
    // prepared statements). Owned by this class — do not PQfinish.
    PGconn*     native() const { return conn_; }

    // True if PQstatus reports the connection OK. Cheap, but lags reality —
    // libpq can still report OK for some time after the peer drops. Use alive()
    // to actually detect a dead remote connection.
    bool ok() const;

    // Actively probe the connection with a trivial round-trip query. Unlike
    // ok(), this performs real I/O, so it reliably detects a connection whose
    // backend was terminated or whose peer went away (network flap, VPS
    // restart). Bounded by the TCP keepalive settings baked into the conninfo
    // when the peer is silently gone. Returns false on any failure.
    bool alive();

    // Re-establish the connection in place via libpq PQreset, reusing the
    // original parameters. The PGconn* from native() stays valid afterward, so
    // holders (the connection holders) don't need to be rebuilt. Bounded by the
    // connect_timeout baked into the conninfo.
    void reset();

    // Connection string sans password, for logs.
    std::string label() const;

private:
    PGconn*        conn_ = nullptr;
    DatabaseConfig cfg_;
};

}  // namespace gptimage
