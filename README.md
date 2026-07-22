# GPTImage

An MCP server that bolts OpenAI's `gpt-image-2` onto Claude so you can stop
alt-tabbing between two chat windows like some kind of animal.

You ask Claude for a picture. Claude calls a tool. The picture shows up in the
chat. That is the entire trick. No browser automation, no scraping ChatGPT's
web UI, no cursed Selenium rig held together with duct tape and a prayer. Just
the real API, wrapped in the Model Context Protocol, handing the image back
inline where you can actually see it.

`gpt-image-2` is the model formerly marketed at you as "ChatGPT Images 2.0."
Same thing. It does legible text, 2K output, and does not smear faces into
Lovecraftian horror nearly as often as its ancestors did.

## What it actually does

Two tools. That is it. Scope creep is how projects die in a ditch.

- **`gptimage_generate`** — text goes in, image comes out. Set `quality` to
  `low` when you are just spitballing and `high` when it is going in the deck.
  `auto`, `medium` also exist for the indecisive.
- **`gptimage_edit`** — hand it one or more images plus a prompt and it edits or
  mashes them together. Pass a `mask` for surgical inpainting instead of
  "regenerate the whole damn thing and hope."

Images come back as MCP image blocks, so they render right there in the
conversation instead of vomiting a wall of base64 into your lap.

## The part you will ignore until it bites you

This thing spends real money. Every `high`-quality 1024x1024 is roughly twenty
cents of somebody's OpenAI bill, and that somebody is you. It is single-tenant
by design: your key, your box, your problem. There is a `max_n` cap so an
over-caffeinated agent cannot loop itself into bankruptcy in one call, but the
only cap on quality and frequency is your own self-control. Godspeed.

## The stuff you need

- A C++20 compiler (MSVC 2022, or gcc-13 / clang-17) and CMake 3.25+.
- PostgreSQL 16+. Yes, an image server wants a database, and no, it does not
  store a single one of your images. The Postgres schema holds only the auth
  plumbing: static bearer tokens and the OAuth server's clients, codes, and
  refresh tokens. Everything you generate is ephemeral. Breathe.
- An OpenAI API key with image access, in the `OPENAI_API_KEY` environment
  variable. It never goes in a config file. If you paste your key into a TOML
  and commit it, that is a you problem.

## Build it

Windows (MSVC, multi-config):

```
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --target gptimage_mcp gptimage_cli
```

Binaries land at `build\src\mcp\Release\gptimage_mcp.exe` and
`build\src\cli\Release\gptimage_cli.exe`. The libpq runtime DLLs get copied
next to them automatically, so they run without PostgreSQL's `bin` on PATH.

Linux:

```
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DGPTIMAGE_BUILD_TESTS=OFF
cmake --build build -j"$(nproc)" --target gptimage_mcp gptimage_cli
```

First configure downloads the dependencies (nlohmann/json, spdlog, cpr,
toml++, cpp-httplib, doctest) via CMake FetchContent. Go get a coffee.

## Wire it into Claude, the lazy local way

For local use over stdio, GPTImage never even opens the database: auth is off
(stdio trusts the OS boundary) and the tools only talk to OpenAI. You need a
config with a `[database]` block present (the parser insists on `dbname` and
`user`, even though nothing connects) and your API key in the env. Copy
`config/gptimage.toml.example` to `config/gptimage.toml`, then drop this into
your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "gptimage": {
      "command": "C:\\path\\to\\GPTImage\\build\\src\\mcp\\Release\\gptimage_mcp.exe",
      "args": ["--transport", "stdio"],
      "env": { "OPENAI_API_KEY": "sk-your-key-here" }
    }
  }
}
```

Restart Claude Desktop. Ask it to generate an image. Watch the magic. Or watch
the error message, in which case read it, because it will tell you exactly what
you did wrong.

## Wire it into Claude, the grown-up remote way

Run it as an HTTP server on a box with a domain, front it with a TLS proxy, and
add it to claude.ai as a custom connector. GPTImage ships an embedded OAuth 2.1
authorization server, so the "add custom connector" flow just works: point it at
`https://your-host/mcp`, sign in on the built-in login page, done. Set a login
password with `gptimage_cli passwd operator` first.

Prefer a static token? Mint one with `gptimage_cli tokens add` and bridge stdio
to the remote server with `mcp-remote`:

```json
{
  "mcpServers": {
    "gptimage": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://your-host/mcp",
               "--header", "Authorization:${GPTIMG_AUTH}"],
      "env": { "GPTIMG_AUTH": "Bearer gpt_your_token_here" }
    }
  }
}
```

## Deploy to a VPS without crying

Everything you need is in `deploy/` and `scripts/`:

- `deploy/gptimage-mcp.service` — hardened systemd unit, binds `127.0.0.1:17718`.
- `deploy/Caddyfile.gptimage.snippet` — Caddy site block, terminates TLS, proxies
  only the MCP + OAuth paths, 404s everything else.
- `deploy/fail2ban/` — jails that ban whoever brute-forces your login or spams
  the DCR endpoint.
- `scripts/deploy_vps.sh` — pulls from git, builds, runs migrations, atomically
  flips a release symlink, health-checks, and rolls itself back if the new
  build faceplants.
- `scripts/install_linux.sh` — the one-time host-setup checklist.

One-time database bootstrap:

```
createdb -U postgres gptimage
psql -U postgres -d gptimage -v gptimage_pw='...' -f sql/setup/create_role.sql
gptimage_cli migrate
gptimage_cli oauth keygen
```

Secrets live in `/etc/gptimage/env` as an EnvironmentFile: `GPTIMAGE_DB_PASSWORD`
and `OPENAI_API_KEY`. Not in the TOML. We have been over this.

## Configure the knobs

All of it lives in `config/gptimage.toml` (see the `.example`). The `[image]`
section is the interesting bit: default size, default quality, output format,
the model id (bump it when OpenAI ships the next one and change nothing else),
and `max_n` to keep runaway agents from setting your credit card on fire.

## Test

```
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

The unit tests cover config parsing, the auth/grant model, JWT signing, the
OAuth PKCE helpers, and password hashing. They do not call OpenAI, so they cost
nothing and prove nothing about whether the pictures are any good.

## License

GPLv3. It is in `LICENSE`, all 553 glorious lines of it. Use it, fork it, ship
it, but if you distribute it you share the source. Those are the rules. Take
them up with the Free Software Foundation, not me.

Built by Locke Werks.
