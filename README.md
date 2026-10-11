# Loom Computer

Loom Computer is the agent and image behind Loom's computer: a containerized
Linux desktop that a teammate drives through one MCP server. It is local
infrastructure, not a special agent type. Loom grants the machine's `/mcp`
endpoint to a teammate like any other server, and the person sees and drives
the same desktop through the viewer the machine serves. The image releases on
its own schedule; this skeleton is release line **0.10.3**, Loom's
`COMPUTER_VERSION` floor.

## Contract summary

Source of truth: Loom's `docs/computer.md`. Phases 0-2 implement:

| Route | Behavior |
| --- | --- |
| `GET /health` | Open liveness probe, `200 {"status":"ok","version":"0.10.3"}`. |
| `POST /mcp` | Needs `Authorization: Bearer $LOOM_COMPUTER_TOKEN`, else JSON 401 for every method (as does every route other than `GET /health` and `GET /`). JSON-RPC body. `tools/call` `state` with `action: "guide"` returns the release skill (`name`, `version`, bare-hex `sha256` of `skill`, and the `skill` text); the other tools are below. `initialize` and `tools/list` are answered. A tool that refuses or fails answers a result with `isError: true` and a text reason; an unknown tool is JSON-RPC `-32602`, an unknown method `-32601`. |
| `X-Computer-Holder` | Names the teammate for leases and queued runs. Phase 0 only logs it at debug level. |
| `GET /` | The viewer: a single page (no external assets, CSP-pinned inline script) that reads the token from the URL fragment, opens `/ws`, and draws frames on a canvas. |
| `GET /ws` | Needs `?token=` matching the bearer. Bad token: accepted and closed with 1008 (so the peer sees the code). Good token: a text `{"type":"hello","width","height"}`, then binary JPEG frames, newest only, sent when the screen changed. The viewer sends **text only** (JSON; binary is closed with 1003): `{"t":"pointer","x","y","buttons"}` (DOM `buttons` bitmask), `{"t":"wheel","dy"}`, `{"t":"key","key","down"}` (DOM `key` values). Held keys/buttons are released when the socket closes. No X display: 1011. |

Uvicorn access logging is off and `?token=` values are redacted from its remaining logs.

Port 8787, bound to `0.0.0.0` inside the container (Loom publishes it on
loopback). The server refuses to start if `LOOM_COMPUTER_TOKEN` is unset.
Nothing runs as root: the image uses the `agent` user (UID 1000) with
`/home/agent/workspace` as its working directory.

Phase 3 adds the secrets routes below. Not implemented (not in Phase 3's
scope): `DELETE /logins/{name}` and `state login_load`.

### `state login_load` (left unimplemented, deliberately)

The contract names it once, as how the desk's cookie import
(`import-<browser>-<profile>`) is "loaded", and defines nothing else: not its
arguments, not where a saved login's cookies are kept, not what it answers.
Inventing a store and a format here would be guessing at an interface the
desk has to match byte for byte, so `state` still answers
`state: unknown action login_load`. `DELETE /logins/{name}` is its
counterpart and is left for the same reason (and the 404 it answers is the
contract's own signal that a release predates it).

## Secrets (Phase 3)

| Route | Behavior |
| --- | --- |
| `PUT /secrets` | Bearer. The whole granted set, a JSON object of name to secret, replacing the last. A string is a variable; `{"kind":"login","sites":[...],"username","password","totp"?}`; `{"kind":"passkey","rpId","credentialId","privateKey","userHandle"?,"userName"?,"userDisplayName"?}` (`credentialId`, `privateKey`, `userHandle` base64 or base64url; `totp` base32 or an `otpauth://` URI). Answers `200 {"ok":true,"variables":n,"logins":n,"passkeys":n}`; a malformed set is `400 {"error"}` (naming the secret and the field, never a value) and leaves the previous set. There is **no GET**. |
| `PUT /passkeys/registration` | Bearer. `{"rpId"}` arms the computer for ten minutes for that site and readies the browser (a tab exists, authenticators attached). `200 {"status":"armed","rpId","expiresAt"}`. |
| `GET /passkeys/registration` | `{"status":"idle"}`, `{"status":"armed",...}`, `{"status":"asked","ask":{id,rpId,origin,rpName?,userName?,userDisplayName?,askedAt}}`, `{"status":"approved"}`, then `{"status":"registered","passkey":{kind,rpId,credentialId,privateKey,userHandle?,userName?,userDisplayName?}}`. |
| `POST /passkeys/registration/answer` | `{"id","approved"}`. 409 when that request is not waiting (including after expiry). Denied: the site gets `NotAllowedError` and the arming ends. |
| `DELETE /passkeys/registration` | Ends the arming (the desk does this after storing the passkey). |

Design:

- **Memory only.** The set lives in `SecretStore` (`loom_computer/secrets.py`);
  nothing touches disk and a restart clears it. Routes parse bodies by hand so
  a framework validation error can never echo a value.
- **Variables** are merged into the environment of every `shell` / `files
  run` job (`Tools._job_env`) after the workspace's `.loom/env`, skipping
  names that are not valid identifiers and `LOOM_COMPUTER*`. They are never
  written to the workspace, so the desk's preparation-job environment
  (`.loom/env`) cannot contain them. Jobs still get an environment built from
  constants, so they never inherit the bearer.
- **Redaction.** Every tool answer (text blocks and structured content,
  errors included) has each granted value (variables, logins' username /
  password / totp secret, passkeys' key material) replaced by `[REDACTED]`,
  also in its JSON-escaped form; log records are masked the same way. Limits:
  screenshots are pixels, and a job that re-encodes a value (base64, reversal)
  can print a form the mask does not know.
- **Logins.** `browser fill {selector, secret, field?}`; the page origin is
  read and checked against `sites` and the typing happens in the same page
  evaluation guarded by that origin, so a navigation cannot slip between. A
  site entry covers its host and hosts within it; a bare host means https
  (plain http only for `localhost`/`127.0.0.1`); an entry with a scheme or
  port must match those too.
- **Passkeys.** A background watcher keeps one long-lived DevTools socket per
  tab (a virtual authenticator exists only as long as the socket that made
  it), with a CTAP2 internal authenticator with automatic presence/verification
  simulation, loaded with the granted passkeys; tabs are attached again
  before any browser tool call and every second. Two Chromium behaviors
  shape this (found against the real browser): its window has no OS focus in
  this desktop, and a WebAuthn ceremony waits for a focused page, so the
  showing tab is brought to front (no tab is switched); and the browser
  drops the WebAuthn domain's state around every navigation's load, which
  orphans a ceremony started before it. The page script therefore holds each
  `get()` (and an approved `create()`) until the document has loaded and the
  authenticator has survived it, then lets it through; a `get()` the computer
  never answers goes ahead after 8 s.
- **Registration guard.** A script injected in every document wraps
  `CredentialsContainer.prototype.create` and reports through a CDP binding;
  the computer decides. Only while armed, for that rpId, from an origin within
  it, one at a time, is a request parked (`asked`); everything else gets a
  `NotAllowedError` immediately. On approval the page's own `create()` runs
  and the authenticator's `credentialAdded` event yields the record. Anything
  that appears in an authenticator without an approval for this arming (or for
  another site, or after expiry) is removed on its event and on every look.
  Minted key material joins the redaction masks.

## The tools (Phase 2)

The agent learns these from the skill (`loom_computer/skill.md`), which `state guide`
serves; that file is the reference. Summary:

| Tool | Arguments | Answer |
| --- | --- | --- |
| `state` | `action: "guide"` | `name`, `version`, `sha256`, `skill`. Any other action: `state: unknown action <action>`. |
| `shell` | exactly one of `command` (run by `bash -c`) or `argv` (list, no shell); `cwd`, `timeout` (default 120 s, max 3600) | JSON text: `exit_code`, `stdout`, `stderr`, `timed_out`, `truncated`, `duration_s`. |
| `files` | `action` read / write / list / run; `path`; `content`, `encoding` (utf-8/base64), `append`; run: `args`, `cwd`, `timeout` | read/write/list JSON; run answers like `shell`. Confined to `/home/agent/workspace` (symlinks resolved first). |
| `browser` | `action` navigate / title / text / fill / click; `url`, `selector`, `value`; fill also `secret` (a granted login's name) with `field` username / password / totp | JSON text. Drives the Phase 1 Chromium over CDP. |
| `capture` | `mode` image (<= 1568 px longer edge) / png / tree; `window`, `region` `[x,y,w,h]` | `image`/`png`: an MCP image block plus a text note of the scale. `tree`: accessibility tree as text. |

Design choices:

- **Jobs.** Children of the API in their own session (so a timeout or
  cancellation kills the whole tree); environment built from constants plus
  `<workspace>/.loom/env` (`KEY=VALUE` lines) - never the API's environment,
  which holds the bearer. When the command exits, leftovers in its process
  group are killed; `setsid` opts out. Output keeps head and tail (96 KiB each).
- **Shell string vs argv.** Both are offered and exactly one is required: a
  string for pipelines, a list when an argument must not meet a shell.
- **Browser over CDP, not X injection.** supervisord starts Chromium with
  `--remote-debugging-port=9222` on loopback (not published; the page Host
  and Origin checks keep web pages out). Each call attaches to the most
  recently active page target, so the person's own tabs are what the agent sees.
- **Capture** grabs the X root with `mss` (the same path as the viewer), crops
  to the window geometry (EWMH client list; title or class substring, or a
  1-based index) and then the region, and scales with Lanczos. `tree` is
  `Accessibility.getFullAXTree`.

## The desktop (Phase 1)

`loom_computer.init` is PID 1. It runs `supervisord` (pip-pinned, as `agent`)
for the three desktop processes and forks the API next to it:

| Process | Choice | Why |
| --- | --- | --- |
| X server | `Xvfb :99`, 1280x800x24, no TCP | Headless, in-memory framebuffer, nothing to configure. |
| Window manager | Openbox, no panel/menu, windows maximized | Full desktop semantics (focus, move, resize, EWMH that Chromium expects) for a few MB. Xfce/LXDE would add a panel, session manager, and compositor-era dependencies (hundreds of MB) that nothing here uses. |
| Browser | Debian's `chromium`, `--no-sandbox` | `--no-sandbox` because the container runs `--cap-drop=ALL` + the default seccomp profile, which forbids the user namespaces Chromium's sandbox needs; the container is the boundary. |
| API | `loom_computer.init` forks `loom_computer.app.main` (uvicorn) | Serves `/health`, `/mcp`, `/`, `/ws`. Not under supervisord, see below. |

Supervisor: supervisord over s6/runit because it is one pinned wheel (no extra
apt packages, no overlay of init scripts), restarts crashed children, reaps
and its config is a single readable file. Desktop processes are started
without the token (and again with `env -u LOOM_COMPUTER_TOKEN`) so the
browser and anything it spawns never inherit the bearer.

**Token isolation.** Everything shares the `agent` UID: `--cap-drop=ALL` and
`no-new-privileges` leave no way to run the API as a second user, and nothing
runs as root. Instead the two token holders (`init` and the API) mark
themselves non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`), which makes their
`/proc/<pid>/environ`, `mem` and ptrace need privileges `agent` lacks. The
flag does not survive `exec`, so `init` holds the token without ever
exec-ing and the API is a plain `fork` of it. Anything the API later spawns
must be started with the token removed from its environment.

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
3. **Secrets**: `PUT /secrets`, logins, passkeys, redaction. (this)
4. **Release pipeline**: tagged releases published to GHCR.
5. **Three-agent integration test**: three teammates sharing one computer
   with leases and queued runs.
