#include <gptimage/db.hpp>

#include <libpq-fe.h>

#include <sstream>
#include <stdexcept>
#include <utility>

namespace gptimage {

namespace {

std::string build_conninfo(const DatabaseConfig& cfg, bool include_password) {
    // libpq accepts whitespace-separated key=value pairs with single-quoted
    // values. Inputs here originate from our own TOML — no untrusted data, so
    // minimal escaping is sufficient for backslash and single-quote.
    auto esc = [](const std::string& v) {
        std::string out;
        out.reserve(v.size() + 2);
        out.push_back('\'');
        for (char c : v) {
            if (c == '\\' || c == '\'') out.push_back('\\');
            out.push_back(c);
        }
        out.push_back('\'');
        return out;
    };

    std::ostringstream os;
    os << "host="            << esc(cfg.host)
       << " port="           << cfg.port
       << " dbname="         << esc(cfg.dbname)
       << " user="           << esc(cfg.user);
    if (include_password && !cfg.password.empty()) {
        os << " password="   << esc(cfg.password);
    }
    if (!cfg.sslmode.empty()) {
        os << " sslmode="    << esc(cfg.sslmode);
    }
    // Bound connect/reset attempts so a dead remote DB (remote DB down, VPS
    // restarting) fails fast instead of hanging the daemon for the OS default.
    os << " connect_timeout=10";
    // TCP keepalives so a silently-dropped connection (network flap where
    // packets just stop) is detected by the OS within ~30s rather than blocking
    // indefinitely — after which queries error and alive()/reset() can recover.
    os << " keepalives=1 keepalives_idle=15 keepalives_interval=5 keepalives_count=3";
    os << " application_name='gptimage'";
    return os.str();
}

}  // namespace

DbConn::DbConn(const DatabaseConfig& cfg) : cfg_(cfg) {
    const std::string conninfo = build_conninfo(cfg_, /*include_password=*/true);
    conn_ = PQconnectdb(conninfo.c_str());
    if (!conn_ || PQstatus(conn_) != CONNECTION_OK) {
        std::string err = conn_ ? PQerrorMessage(conn_) : "null connection";
        if (conn_) {
            PQfinish(conn_);
            conn_ = nullptr;
        }
        throw std::runtime_error("db: connect failed: " + err);
    }
}

DbConn::~DbConn() {
    if (conn_) PQfinish(conn_);
}

DbConn::DbConn(DbConn&& o) noexcept : conn_(o.conn_), cfg_(std::move(o.cfg_)) {
    o.conn_ = nullptr;
}

DbConn& DbConn::operator=(DbConn&& o) noexcept {
    if (this != &o) {
        if (conn_) PQfinish(conn_);
        conn_   = o.conn_;
        cfg_    = std::move(o.cfg_);
        o.conn_ = nullptr;
    }
    return *this;
}

bool DbConn::ok() const {
    return conn_ && PQstatus(conn_) == CONNECTION_OK;
}

bool DbConn::alive() {
    if (!conn_) return false;
    PGresult* r = PQexec(conn_, "SELECT 1");
    const bool good = r && PQresultStatus(r) == PGRES_TUPLES_OK;
    if (r) PQclear(r);
    return good;
}

void DbConn::reset() {
    // PQreset closes and reopens the connection using the original parameters,
    // keeping the same PGconn* so holders of native() stay valid. If the server
    // is still unreachable the connection lands in CONNECTION_BAD — callers
    // gate on ok() and try again later.
    if (conn_) PQreset(conn_);
}

std::string DbConn::label() const {
    return build_conninfo(cfg_, /*include_password=*/false);
}

}  // namespace gptimage
