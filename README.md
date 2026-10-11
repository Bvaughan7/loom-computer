# Loom Computer

Loom Computer is the agent and image behind Loom's computer: a containerized
Linux desktop that a teammate drives through one MCP server. It is local
infrastructure, not a special agent type. Loom grants the machine's `/mcp`
endpoint to a teammate like any other server, and the person sees and drives
the same desktop through the viewer the machine serves. The image releases on
its own schedule; this skeleton is release line **0.10.3**, Loom's
`COMPUTER_VERSION` floor.

## Contract summary

Source of truth: Loom's `docs/computer.md`. Phase 0 implements:

| Route | Behavior |
| --- | --- |
| `GET /health` | Open liveness probe, `200 {"status":"ok","version":"0.10.3"}`. |
| `POST /mcp` | Needs `Authorization: Bearer $LOOM_COMPUTER_TOKEN`, else JSON 401 for every method (as does every route other than `GET /health` and `GET /`). JSON-RPC body. `tools/call` `state` with `action: "guide"` returns the release skill (`name`, `version`, bare-hex `sha256` of `skill`, and the `skill` text); everything else is a JSON-RPC "not implemented" error. `initialize` and `tools/list` are answered minimally. |
| `X-Computer-Holder` | Names the teammate for leases and queued runs. Phase 0 only logs it at debug level. |
| `GET /` | Viewer placeholder page (the real viewer lands in Phase 1). |
| `GET /ws` | Needs `?token=` matching the bearer; then sends a not-implemented message and closes (code 1013). Bad token is accepted and then closed with 1008, so the peer sees the code (closing before the handshake would be an HTTP 403). |

Uvicorn access logging is off and `?token=` values are redacted from its remaining logs.

Port 8787, bound to `0.0.0.0` inside the container (Loom publishes it on
loopback). The server refuses to start if `LOOM_COMPUTER_TOKEN` is unset.
Nothing runs as root: the image uses the `agent` user (UID 1000) with
`/home/agent/workspace` as its working directory.

Not yet implemented: `PUT /secrets`, `/passkeys/registration`,
`DELETE /logins/{name}`, the desktop, browser, and tools.

## Why Python / FastAPI

- The contract is JSON-RPC over HTTP plus a websocket; FastAPI/Starlette cover
  both with little code, and the guide/state surface is a small JSON handler.
- Phase 2's tools (shell, files, browser automation, X11 control) are mostly
  orchestration of subprocesses and Playwright-style libraries, where Python's
  ecosystem is the shortest path; Rust would buy little there.
- Lean image: `python:3.12-slim` plus three pinned packages (fastapi, uvicorn,
  websockets). The heavy parts of later phases (desktop, browser) dwarf the
  runtime choice.

## Build and run

```sh
docker build -t loom-computer .
docker run -d --name loom-computer -p 127.0.0.1:8787:8787 \
  -e LOOM_COMPUTER_TOKEN=test-token loom-computer

curl -s http://127.0.0.1:8787/health
curl -s -X POST http://127.0.0.1:8787/mcp \
  -H 'Authorization: Bearer test-token' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"state","arguments":{"action":"guide"}}}'
```

Tests (any Python 3.12+ with the dev requirements installed):

```sh
pip install -r requirements-dev.txt
python -m pytest
```

## Roadmap

0. **Skeleton**: health, MCP stub, guide, viewer and socket stubs, image. (this)
1. **Desktop + viewer streaming**: a real X desktop, the viewer page and `/ws`.
2. **MCP tools**: `state`, `shell`, `files`, `browser`, and friends over `/mcp`.
3. **Secrets**: `PUT /secrets`, logins, passkeys, redaction.
4. **Release pipeline**: tagged releases published to GHCR.
5. **Three-agent integration test**: three teammates sharing one computer
   with leases and queued runs.
