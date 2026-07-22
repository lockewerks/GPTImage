#include <gptimage/auth.hpp>
#include <gptimage/config.hpp>
#include <gptimage/db.hpp>
#include <gptimage/password_hash.hpp>

#include <libpq-fe.h>
#include <openssl/crypto.h>

#include <cstdio>
#include <string>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <termios.h>
#  include <unistd.h>
#endif

namespace gptimage {

namespace {

void print_usage() {
    std::fprintf(stderr,
        "gptimage_cli passwd <principal> [--stdin]\n"
        "\n"
        "  Set (or reset) the OAuth login password for <principal>. Prompts twice\n"
        "  with echo off; --stdin instead reads one line from stdin (for scripted\n"
        "  provisioning — beware shell history when piping literals).\n"
        "\n"
        "  The principal should match an [[auth.principals]] entry — a password\n"
        "  for an unconfigured principal can log in but resolves no grant, so\n"
        "  every request fails closed.\n");
}

// Read a line from stdin with terminal echo disabled (restored on return).
// Falls back to plain reading when stdin is not a terminal (piped input).
std::string read_password(const char* prompt) {
    std::fprintf(stderr, "%s", prompt);
    std::fflush(stderr);

#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    const bool tty = GetConsoleMode(h, &mode) != 0;
    if (tty) SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
#else
    termios oldt{};
    const bool tty = tcgetattr(STDIN_FILENO, &oldt) == 0;
    if (tty) {
        termios noecho = oldt;
        noecho.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &noecho);
    }
#endif

    std::string line;
    int c;
    while ((c = std::fgetc(stdin)) != EOF && c != '\n') {
        if (c != '\r') line.push_back(static_cast<char>(c));
    }

#ifdef _WIN32
    if (tty) SetConsoleMode(h, mode);
#else
    if (tty) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    std::fprintf(stderr, "\n");
    return line;
}

}  // namespace

int cmd_passwd(const Config& cfg, std::vector<std::string> args) {
    bool from_stdin = false;
    std::string principal;
    for (const auto& a : args) {
        if (a == "--stdin")                 from_stdin = true;
        else if (a == "-h" || a == "--help") { print_usage(); return 0; }
        else if (!a.empty() && a[0] != '-') principal = a;
    }
    if (principal.empty()) {
        print_usage();
        return 1;
    }

    if (!grant_from_config(cfg.auth, principal)) {
        std::fprintf(stderr,
            "passwd: WARNING — no [[auth.principals]] entry named '%s'. The password\n"
            "        will be stored, but logins resolve no grant until one exists.\n",
            principal.c_str());
    }

    std::string password;
    if (from_stdin) {
        int c;
        while ((c = std::fgetc(stdin)) != EOF && c != '\n') {
            if (c != '\r') password.push_back(static_cast<char>(c));
        }
    } else {
        password = read_password("New password: ");
        const std::string again = read_password("Repeat password: ");
        if (password != again) {
            std::fprintf(stderr, "passwd: passwords do not match\n");
            return 1;
        }
    }
    if (password.size() < 12) {
        std::fprintf(stderr, "passwd: refusing a password under 12 characters\n");
        return 1;
    }
    if (password.size() > 1024) {
        std::fprintf(stderr, "passwd: refusing a password over 1024 characters\n");
        return 1;
    }

    const std::string phc = hash_password(password);
    // Scrub the plaintext now that the hash exists — don't leave it on the heap.
    OPENSSL_cleanse(password.data(), password.size());

    DbConn db(cfg.database);
    const char* sql =
        "INSERT INTO gptimage.principal_credentials (principal, password_phc) "
        "VALUES ($1, $2) "
        "ON CONFLICT (principal) DO UPDATE SET "
        "  password_phc = EXCLUDED.password_phc, updated_at = now()";
    const char* params[] = { principal.c_str(), phc.c_str() };
    PGresult* r = PQexecParams(db.native(), sql, 2, nullptr, params, nullptr, nullptr, 0);
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        std::fprintf(stderr, "passwd: upsert failed: %s\n", PQerrorMessage(db.native()));
        PQclear(r);
        return 1;
    }
    PQclear(r);

    std::printf("Password set for principal '%s'.\n", principal.c_str());
    return 0;
}

}  // namespace gptimage
