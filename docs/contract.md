# Loom Computer

Loom Computer is the agent and image behind Loom's computer: a containerized
Linux desktop that a teammate drives through one MCP server. It is local
infrastructure, not a special agent type. Loom grants the machine's `/mcp`
endpoint to a teammate like any other server, and the person sees and drives
the same desktop through the viewer the machine serves. The image releases on
its own schedule; this skeleton's release line is whatever the `VERSION` file
says (0.10.3 as of this writing), Loom's `COMPUTER_VERSION` floor.

## Contract summary

Source of truth: Loom's `docs/computer.md`. Phases 0-2 implement:

| Route | Behavior |
| --- | --- |
| `GET /health` | Open liveness probe, `200 {"status":"ok","version":"<VERSION>"}` (e.g. `"0.10.3"`). |
| `POST /mcp` | Needs `Authorization: Bearer $LOOM_COMPUTER_TOKEN`, else JSON 401 for every method (as does every route other than `GET /health` and `GET /`). JSON-RPC body. `tools/call` `state` with `action: "guide"` returns the release skill (`name`, `version`, bare-hex `sha256` of `skill`, and the `skill` text); the other tools are below. `initialize` and `tools/list` are answered. A tool that refuses or fails answers a result with `isError: true` and a text reason; an unknown tool is JSON-RPC `-32602`, an unknown method `-32601`. |
| `X-Computer-Holder` | Names the teammate for leases and queued runs. Phase 0 only logs it at debug level. |
| `GET /` | The viewer: a single page (no external assets, CSP-pinned inline script) that reads the token from the URL fragment, opens `/ws`, and draws frames on a canvas. |
| `GET /ws` | Needs `?token=` matching the bearer. Bad token: accepted and closed with 1008 (so the peer sees the code). Good token: a text `{"type":"hello","width","height"}`, then binary JPEG frames, newest only, sent when the screen changed. The viewer sends **text only** (JSON; binary is closed with 1003): `{"t":"pointer","x","y","buttons"}` (DOM `buttons` bitmask), `{"t":"wheel","dy"}`, `{"t":"key","key","down"}` (DOM `key` values). Held keys/buttons are released when the socket closes. No X display: 1011. |

Uvicorn access logging is off and `?token=` values are redacted from its remaining logs.

Port 8787, bound to `0.0.0.0` inside the container (Loom publishes it on
loopback). The server refuses to start if `LOOM_COMPUTER_TOKEN` is unset.
Nothing runs as root: the image uses the `agent` user (UID 1000) with
`/home/agent/workspace` as its working directory.

Phase 3 adds the secrets route below. Not implemented (not in Phase 3's
scope): `DELETE /logins/{name}` and `state login_load`. Passkeys (the
registration ceremony and the loading/guard machinery) are held for redesign
(see *Held for redesign*).

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
| `PUT /secrets` | Bearer. The whole granted set, a JSON object of name to secret, replacing the last. A string is a variable; `{"kind":"login","sites":[...],"username","password","totp"?}` (`totp` base32 or an `otpauth://` URI). A `{"kind":"passkey",...}` record is refused: the **whole set** is `400`, naming the secret (never a value), because passkeys are held for redesign. Answers `200 {"ok":true,"variables":n,"logins":n}`; a malformed set is `400 {"error"}` (naming the secret and the field, never a value) and leaves the previous set. There is **no GET**. |

Design:

- **API store in memory only.** The set lives in `SecretStore`
  (`loom_computer/secrets.py`); this API never writes it to disk, and a
  restart clears it. That is the whole guarantee: it covers the store, not
  what happens to a value afterwards. A job holds its variables in its own
  environment and can write them to a file; the workspace and the browser
  profile persist (a login typed into a page may be kept by the browser, and
  and so on). Routes
  parse bodies by hand so a framework validation error can never echo a
  value.
- **Variables** are merged into the environment of every `shell` / `files
  run` job (`Tools._job_env`) after the workspace's `.loom/env`, skipping
  names that are not valid identifiers and `LOOM_COMPUTER*`. They are never
  written to the workspace, so the desk's preparation-job environment
  (`.loom/env`) cannot contain them. Jobs still get an environment built from
  constants, so they never inherit the bearer.
- **Redaction.** Every tool answer (text blocks and structured content,
  errors included) has each granted value (variables, logins' username /
  password / totp secret) replaced by `[REDACTED]`.
  Structured answers are masked in their Python objects *before* JSON
  serialization, so no escape form (`\uXXXX`, `\b`, `\f`, ...) can carry a
  value; log records are masked the same way. Two lifetimes matter:
  replacing the set does not unmask a value a running job still holds (it
  stays masked until that job has finished and answered), a generated TOTP
  code is masked from the moment it is made until its 30 s step ends plus a
  10 s margin.
  `GET /files/download` masks the same values in the bytes it streams
  (`X-Loom-Redacted: best-effort`, no `Content-Length`, `max_bytes` counts
  output bytes). That is byte-level matching of the value as UTF-8 (and its
  JSON-escaped spelling): a value a file holds re-encoded (base64, compressed,
  split across lines, UTF-16) is not recognized. (`files read` with `encoding: base64` masks the raw
  bytes before encoding, so that path is covered.)
  *Accepted limit:* the `X-Loom-Truncated` header comes from a probe made
  before streaming starts, so it reflects the mask set at probe time and can
  be stale if grants change mid-download. The body is always masked with the
  live set and always capped at `max_bytes`; only that header can be stale.
- **Known limits (design questions, left as they are).**
  Variables are in the environment of *every* job, so any job can read and
  print or transform them; redaction only catches the plain forms. The
  browser's CDP port is reachable from inside the container, so a job can
  drive the browser (read a filled password field, or a page's text before
  masking). Screenshots (`capture image`/`png` answers)
  are pixels and are not redacted: the agent must see the screen to work, and
  the person sees the same screen in the viewer. A login's `sites` entry covers its host *and every
  subdomain of it*, so a page anywhere under that host receives the secret.
  Scope logins to real hosts: a bare public suffix (`com`, `co.uk`, ...)
  covers every host beneath it, `attacker.com` included. No public-suffix
  list is built in; a hand-rolled one would be incomplete and misleading.
  `files read` with `encoding: base64` masks values at the byte level before
  encoding. The text redactor is skipped for the encoded content only, to
  keep the base64 valid; the `path` is masked as usual. The `[REDACTED]`
  token is atomic and public: masked output never contains a granted value
  in recoverable form — a value's characters may coincide with the token's
  own text or with a substring of the base64 text, but neither coincidence
  reveals the value. Deliberate probing is a separate matter: an agent that
  writes a guessed value and reads it back can tell whether the guess
  matched a granted value (it comes back masked). That confirmation oracle
  is inherent to any output masking; this design's boundary is accidental
  exposure, not a malicious agent. A granted value must not contain the
  literal `[REDACTED]`; such a set is rejected at PUT.
- **Logins.** `browser fill {selector, secret, field?}`; the page origin is
  read and checked against `sites` and the typing happens in the same page
  evaluation guarded by that origin, so a navigation cannot slip between. A
  site entry covers its host and hosts within it; a bare host means https
  (plain http only for `localhost`/`127.0.0.1`); an entry with a scheme or
  port must match those too.
## Releasing

`VERSION` (repo root, plain `X.Y.Z`) is the single source of truth.
`loom_computer.VERSION` reads it (so `/health`, the MCP `serverInfo` and
`state action=guide` serve it), the Dockerfile copies it into the image and
takes it as `--build-arg VERSION` for the `org.opencontainers.image.version`
label (the build fails if the arg and the file disagree), and the workflow
reads it for the build arg and refuses a tag that does not match it.

### Process

1. `./scripts/release.sh <version>`: validates semver, requires a clean tree
   and an unused tag, writes `VERSION`, commits `release: <version>`, tags
   `v<version>` and pushes the tag (it asks first; `--yes` skips that). If
   `VERSION` already holds the version, no commit is made and the tag lands
   on HEAD.
2. The tag push triggers `.github/workflows/release.yml`, two jobs. `build`
   (`contents: read` only) checks tag == `VERSION` and that both are plain
   semver (no leading zeros, same rule as the script), builds the image
   **once**, smoke-checks that image's guide serves that version, and hands
   it to `publish` as an artifact (`docker save`) along with its image ID.
   `publish` (tag push only; `contents: write`, `packages: write`) loads the
   artifact, fails unless the image ID equals the smoke-checked one, pushes
   `ghcr.io/bvaughan7/loom-computer:<version>` with `GITHUB_TOKEN`, and
   creates the GitHub release `v<version>` whose notes carry the image
   reference and the pushed digest (and a `@sha256:` pinned form). Nothing
   is rebuilt between the smoke check and the push, so the published digest
   is the image that was checked.
3. The desk discovers it: `releases.rs` lists the repo's releases and parses
   `tag_name`; the desk derives the image as
   `ghcr.io/bvaughan7/loom-computer:<tag without v>`, and learns the running
   release from `guide.version`.

Dry runs push nothing: `./scripts/release.sh --dry-run [<version>]` builds the
image locally as `ghcr.io/bvaughan7/loom-computer:<version>` (from a copy of
the tree, so it works before `VERSION` is bumped and changes no git state),
starts it and checks the guide serves `<version>`. In CI, `workflow_dispatch`
with an `image_tag` runs only the read-only `build` job (same build and
smoke check); the `publish` job, the only one with write permissions, is
skipped.

### `latest` is not tagged

Only `:<version>` is pushed. The desk never uses `latest` (it resolves a
concrete release and a pinned image is used as written), so the tag would be
read by nobody, and a moving tag on a private package makes "what is
running" ambiguous. Add it later only if a consumer needs it.

### Auth while the package is private

The repository and package are private. Pulling needs `docker login ghcr.io`
with a classic PAT that has `read:packages` (`write:packages` to push by
hand; CI uses `GITHUB_TOKEN`, no PAT). While private, the desk host must be
logged in and the desk should use pinned image references
(e.g. `ghcr.io/bvaughan7/loom-computer:0.10.3`, as in its pin setting): the
unauthenticated GitHub releases listing cannot see a private repo's
releases, so "Newest" discovery works only once the repo is public or the
desk is given a token, and the floor/pins work regardless.

### First real release, what Bryan does

As of this writing `VERSION` says 0.10.3 and no tag exists, so nothing needs
bumping (use the number in `VERSION` wherever 0.10.3 appears below).

1. Merge this branch (`phase4/release-pipeline`) to the main branch.
2. In the repo's Settings > Actions > General, give workflows read and write
   permissions (or leave the default and rely on the workflow's own
   `permissions:` block, which is sufficient).
3. Optionally rehearse: Actions > release > Run workflow (`image_tag`
   `dryrun`), and/or `./scripts/release.sh --dry-run`.
4. `./scripts/release.sh <VERSION>` (0.10.3 at time of writing). Watch the run (`gh run list --workflow
   release.yml`).
5. After the first push, GHCR creates the package private and linked to the
   repo; check Packages > loom-computer > Package settings (visibility,
   and that the repo has Actions write access to it).
6. On the desk host: `docker login ghcr.io` (PAT with `read:packages`), then
   `docker pull ghcr.io/bvaughan7/loom-computer:<VERSION>`.

## Held for redesign

All passkey code is held, and none ships in this release: no registration
ceremony, no virtual-authenticator loading, no guard. `PUT /secrets` refuses a
`kind: "passkey"` record (whole set `400`, naming the secret), the
`/passkeys/registration*` routes answer `404`, and the served guide says
passkeys are not supported. Two designs are held, each with known issues a
redesign must start from.

### (a) Passkey registration ceremony

Was `PUT` / `GET` / `DELETE /passkeys/registration`, `POST
/passkeys/registration/answer`, and a page-side guard parking
`navigator.credentials.create()`.

1. **Tab-secret harvesting.** The guard released parked requests through
   `window.__loomRelease`, authenticated by a per-tab secret shared with the
   page script. A page that harvests the secret can forge guard reports.
2. **Clean-slate race.** The authenticator was snapshotted and emptied at
   approval and the first credential added afterwards was taken as the mint;
   a credential added between snapshot and release races with it.
3. **Nonce eviction at 4097.** Single-use ask nonces lived in a set bounded
   at 4096; the 4097th evicts the oldest, which can then be replayed.

### (b) Passkey loading and guard

Was a CDP watcher loading granted passkeys into a virtual
authenticator per tab, plus a guard: `Permissions-Policy:
publickey-credentials-create=()` injected on document responses via the Fetch
domain, a Fetch-pause readiness hold, and removal of ungranted credentials.
All of it was passkey-specific, so nothing generic of it remains.

1. **Popup interception timing.** A popup can load before the polling-based
   interception is enabled for it, so its first document is unguarded.
2. **Cross-process subframes.** Out-of-process subframes sit outside the
   interception scope and get neither the policy header nor the hold.
3. **Fail-open readiness hold.** After its retries the hold releases the
   document without a ready authenticator, so a `get()` at load can miss.
4. **`about:blank` cleanup race.** Cleanup of ungranted credentials on a tab
   at `about:blank` races with the document that replaces it.

### `state login_load`

Still unimplemented: the contract names it with no defined arguments, store
or answer, and this release does not invent one (see above).

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
3. **Secrets**: `PUT /secrets`, variables, logins, redaction. (this; passkeys held)
4. **Release pipeline**: tagged releases published to GHCR.
5. **Three-agent integration test**: three teammates sharing one computer
   with leases and queued runs.
