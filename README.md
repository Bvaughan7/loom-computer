# Loom Computer

Loom Computer is the agent and image behind Loom's computer: a containerized
Linux desktop that a teammate drives through one MCP server. It is local
infrastructure, not a special agent type. Loom grants the machine's `/mcp`
endpoint to a teammate like any other server, and the person sees and drives
the same desktop through the viewer the machine serves. The image releases on
its own schedule; this skeleton is release line **0.10.3**, Loom's
`COMPUTER_VERSION` floor.

## Contract summary

Source of truth: Loom's `docs/computer.md`. Phases 0 and 1 implement:

| Route | Behavior |
| --- | --- |
| `GET /health` | Open liveness probe, `200 {"status":"ok","version":"0.10.3"}`. |
| `POST /mcp` | Needs `Authorization: Bearer $LOOM_COMPUTER_TOKEN`, else JSON 401 for every method (as does every route other than `GET /health` and `GET /`). JSON-RPC body. `tools/call` `state` with `action: "guide"` returns the release skill (`name`, `version`, bare-hex `sha256` of `skill`, and the `skill` text); everything else is a JSON-RPC "not implemented" error. `initialize` and `tools/list` are answered minimally. |
| `X-Computer-Holder` | Names the teammate for leases and queued runs. Phase 0 only logs it at debug level. |
| `GET /` | The viewer: a single page (no external assets, CSP-pinned inline script) that reads the token from the URL fragment, opens `/ws`, and draws frames on a canvas. |
| `GET /ws` | Needs `?token=` matching the bearer. Bad token: accepted and closed with 1008 (so the peer sees the code). Good token: a text `{"type":"hello","width","height"}`, then binary JPEG frames, newest only, sent when the screen changed. The viewer sends **text only** (JSON; binary is closed with 1003): `{"t":"pointer","x","y","buttons"}` (DOM `buttons` bitmask), `{"t":"wheel","dy"}`, `{"t":"key","key","down"}` (DOM `key` values). Held keys/buttons are released when the socket closes. No X display: 1011. |

Uvicorn access logging is off and `?token=` values are redacted from its remaining logs.

Port 8787, bound to `0.0.0.0` inside the container (Loom publishes it on
loopback). The server refuses to start if `LOOM_COMPUTER_TOKEN` is unset.
Nothing runs as root: the image uses the `agent` user (UID 1000) with
`/home/agent/workspace` as its working directory.

Not yet implemented: `PUT /secrets`, `/passkeys/registration`,
`DELETE /logins/{name}`, and the MCP tools (browser/shell/files).

## The desktop (Phase 1)

`supervisord` (pip-pinned, runs as `agent`) keeps four processes up:

| Process | Choice | Why |
| --- | --- | --- |
| X server | `Xvfb :99`, 1280x800x24, no TCP | Headless, in-memory framebuffer, nothing to configure. |
| Window manager | Openbox, no panel/menu, windows maximized | Full desktop semantics (focus, move, resize, EWMH that Chromium expects) for a few MB. Xfce/LXDE would add a panel, session manager, and compositor-era dependencies (hundreds of MB) that nothing here uses. |
| Browser | Debian's `chromium`, `--no-sandbox` | `--no-sandbox` because the container runs `--cap-drop=ALL` + the default seccomp profile, which forbids the user namespaces Chromium's sandbox needs; the container is the boundary. |
| API | `python -m loom_computer` (uvicorn) | Serves `/health`, `/mcp`, `/`, `/ws`. |

Supervisor: supervisord over s6/runit because it is one pinned wheel (no extra
apt packages, no overlay of init scripts), restarts crashed children, reaps
zombies as PID 1, and its config is a single readable file. Desktop processes
are started with `env -u LOOM_COMPUTER_TOKEN` so the browser and anything it
spawns never inherit the bearer.

**Stream protocol, not VNC/noVNC.** Loom's contract says the Remote door
carries frames to a phone as they are and passes only *text* back. An RFB
(VNC) stream needs binary client messages, so noVNC would not survive that
door. `/ws` is therefore frames out (JPEG, `mss` + Pillow) and JSON text input
in (XTEST via `python-xlib`): no VNC server, no websockify, no JS dependency.
One capture loop is shared by all viewers and runs only while one is
connected.

Pinning: Python deps are exact in `requirements.txt`; the base image is pinned
by digest; Debian packages come from the dated `snapshot.debian.org` archive
the base image was built against (20261005), so they cannot drift.

Image tests: `LOOM_TEST_IMAGE=<tag> python -m pytest tests/test_image.py`
(needs docker); `tests/test_desktop_smoke.py` runs against a host `Xvfb`.

## Why Python / FastAPI

- The contract is JSON-RPC over HTTP plus a websocket; FastAPI/Starlette cover
  both with little code, and the guide/state surface is a small JSON handler.
- Phase 2's tools (shell, files, browser automation, X11 control) are mostly
  orchestration of subprocesses and Playwright-style libraries, where Python's
  ecosystem is the shortest path; Rust would buy little there.
- Lean runtime: `python:3.12-slim` plus a handful of pinned packages. The heavy parts of later phases (desktop, browser) dwarf the
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
1. **Desktop + viewer streaming**: a real X desktop, the viewer page and `/ws`. (this)
2. **MCP tools**: `state`, `shell`, `files`, `browser`, and friends over `/mcp`.
3. **Secrets**: `PUT /secrets`, logins, passkeys, redaction.
4. **Release pipeline**: tagged releases published to GHCR.
5. **Three-agent integration test**: three teammates sharing one computer
   with leases and queued runs.
