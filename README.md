<p align="center">
  <img src="assets/loom-computer-logo.webp" width="160" alt="Loom Computer">
</p>

<h1 align="center">Loom Computer</h1>

<p align="center">
  <strong>A containerized Linux desktop that a coding agent drives.</strong>
</p>

<p align="center">
  <a href="LICENSE-APACHE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="Apache-2.0"></a>
  <img src="https://img.shields.io/badge/docker-ghcr.io-2496ED?logo=docker&logoColor=white" alt="GHCR">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white" alt="Python 3.12">
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-features">Features</a> ·
  <a href="#-architecture">Architecture</a> ·
  <a href="#-releases">Releases</a> ·
  <a href="#-contributing">Contributing</a>
</p>

---

## ⚡ Overview

Loom Computer is the machine behind [Loom](https://github.com/Bvaughan7/loom)'s
computer: a full Linux desktop in a container — a real X session running real
Chromium — that a teammate drives through a single MCP server. It is local
infrastructure, not a special agent type. Loom grants the machine's `/mcp`
endpoint to a teammate like any other server, and you see and drive the very
same desktop through the live viewer the machine serves.

One image, one contract, versioned releases. The agent gets a shell, files, a
real browser, and screen capture; you get the screen.

## ✨ Features

- **Real desktop** — Xvfb + Openbox + Chromium at 1280×800, streamed as JPEG
  frames over a websocket. No VNC, no noVNC, no browser embedded in your app.
- **MCP tools** — `shell`, `files`, `browser` (via CDP), `capture`, and
  `state` over one JSON-RPC `/mcp` endpoint.
- **Live viewer** — a single self-contained page. The token travels in the URL
  fragment, frames draw on a canvas, pointer and keyboard input go back as
  JSON.
- **Secrets, minimal and safe** — variables and site-scoped logins are granted
  with `PUT /secrets`, live in memory only, can never be read back, and are
  redacted from every tool answer and log line.
- **Non-root by design** — everything runs as the `agent` user (UID 1000), and
  the server refuses to start without `LOOM_COMPUTER_TOKEN`.
- **Versioned releases** — `VERSION` is the single source of truth. Releases
  are immutable tags on GHCR; there is no moving `latest`.

## 🚀 Quick Start

```sh
docker run -d --name loom-computer -p 127.0.0.1:8787:8787 \
  -e LOOM_COMPUTER_TOKEN="$(openssl rand -hex 32)" \
  ghcr.io/bvaughan7/loom-computer:0.10.3

curl -s http://127.0.0.1:8787/health
# {"status":"ok","version":"0.10.3"}
```

Open `http://127.0.0.1:8787/#token=<your-token>` for the live viewer. Every
route except `GET /health` and `GET /` requires
`Authorization: Bearer <token>`.

## 🏗 Architecture

```
┌──────────────┐     /mcp (JSON-RPC)        ┌───────────────────┐
│  Loom desk   │ ─────────────────────────▶ │  FastAPI server   │
│  (teammate)  │ ◀───────────────────────── │  :8787            │
└──────────────┘   shell, files, browser,  └────────┬──────────┘
                   capture, state                   │
                                                    ▼
┌──────────────┐     /ws JPEG frames        ┌───────────────────┐
│  You         │ ◀───────────────────────── │  Xvfb + Openbox   │
│  (viewer)    │     pointer/key JSON ────▶ │  + Chromium       │
└──────────────┘                            └───────────────────┘
```

The full endpoint contract lives in [`docs/contract.md`](docs/contract.md).

## 📦 Releases

`VERSION` is the single source of truth. Pushing a `vX.Y.Z` tag builds the
image exactly once, smoke-checks that the served guide reports the tagged
version, then publishes that same image to GHCR and creates a GitHub release
with the image reference and digest. Nothing is rebuilt between check and
publish, so the digest you pull is the image that was tested. Pin a version —
`latest` is never tagged.

## 🔧 Build from source

```sh
docker build -t loom-computer .
docker run -d --name loom-computer -p 127.0.0.1:8787:8787 \
  -e LOOM_COMPUTER_TOKEN="$(openssl rand -hex 32)" \
  loom-computer
```

Tests (Python 3.12+):

```sh
pip install -r requirements-dev.txt
python -m pytest
```

## 🤝 Contributing

Issues and pull requests are welcome. If the code and `docs/contract.md`
disagree, the code wins and the doc gets fixed in the same change.

## License

Licensed under the Apache License 2.0 or the MIT license, at your option -- same as [Loom](https://github.com/Bvaughan7/loom).
