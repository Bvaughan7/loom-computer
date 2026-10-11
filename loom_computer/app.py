"""HTTP surface of the computer: /health, /mcp, /, /ws."""

import asyncio
import base64
import contextlib
import copy
import hashlib
import hmac
import json
import logging
import os
import re
import sys
import threading
import weakref
from importlib import resources

from fastapi import FastAPI, Request, WebSocket
from starlette.websockets import WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from . import VERSION
from .browser import Browser
from .desktop import Desktop, FrameHub, InputSession
from .errors import ToolError
from .tools import DEFINITIONS, Tools

PORT = 8787
WORKSPACE = "/home/agent/workspace"
SKILL_NAME = "loom-computer"
log = logging.getLogger("loom_computer")


def _viewer_page() -> tuple[str, str]:
    """The viewer HTML and a CSP that allows exactly its inline script/style."""
    html = resources.files(__package__).joinpath("viewer.html").read_text("utf-8")

    def digest(tag: str) -> str:
        body = re.search(rf"<{tag}>(.*?)</{tag}>", html, re.S).group(1)
        return "'sha256-" + base64.b64encode(
            hashlib.sha256(body.encode("utf-8")).digest()).decode() + "'"

    csp = ("default-src 'none'; img-src blob: data:; connect-src 'self' ws: wss:; "
           f"script-src {digest('script')}; style-src {digest('style')}; "
           "base-uri 'none'; form-action 'none'")
    return html, csp


def _download_error(status: int, message: str) -> JSONResponse:
    # `error` is the human-facing reason the desk shows; `code` is the
    # machine-readable class.
    return JSONResponse({"error": message, "code": "download_failed"},
                        status_code=status)


class _OwnedFd:
    """A descriptor with exactly one closer, safe against a read in flight."""

    def __init__(self, fd: int):
        self._fd: int | None = fd
        self._lock = threading.Lock()

    def read(self, n: int) -> bytes:
        with self._lock:
            return os.read(self._fd, n) if self._fd is not None else b""

    def close(self) -> None:
        with self._lock:
            if self._fd is not None:
                fd, self._fd = self._fd, None
                os.close(fd)


class _FdResponse(StreamingResponse):
    """Closes its descriptor when the response ends, is cancelled, or is
    dropped without ever being sent."""

    def __init__(self, owned: _OwnedFd, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._finalizer = weakref.finalize(self, owned.close)
        self._owned = owned

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._owned.close()


def _skill_document() -> str:
    return resources.files(__package__).joinpath("skill.md").read_text("utf-8")


def guide() -> dict:
    """The release's own skill with its version and checksum.

    The shape is the manifest Loom's guide parser reads: `version`, a bare
    hex `sha256` of the `skill` text.
    """
    document = _skill_document()
    return {
        "name": SKILL_NAME,
        "version": VERSION,
        "sha256": hashlib.sha256(document.encode("utf-8")).hexdigest(),
        "skill": document,
    }


def _rpc_result(rpc_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _rpc_error(rpc_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


INVALID_REQUEST = -32600


def _invalid(rpc_id, why: str) -> dict:
    return _rpc_error(rpc_id, INVALID_REQUEST, f"invalid request: {why}")


async def _handle_rpc(message: dict, tools: Tools) -> dict | None:
    """Answer one JSON-RPC message; None for a notification (no `id` member)."""
    has_id = "id" in message
    rpc_id = message.get("id")
    if isinstance(rpc_id, bool) or not isinstance(rpc_id, (str, int, type(None))):
        return _invalid(None, "id must be a string, number or null")
    if message.get("jsonrpc") != "2.0":
        return _invalid(rpc_id, 'jsonrpc must be "2.0"')
    method = message.get("method")
    if not isinstance(method, str):
        return _invalid(rpc_id, "method must be a string")
    params = message.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _invalid(rpc_id, "params must be an object")
    if not has_id:  # notification: no response
        return None

    if method == "initialize":
        version = params.get("protocolVersion", "2025-03-26")
        if not isinstance(version, str):
            return _invalid(rpc_id, "protocolVersion must be a string")
        return _rpc_result(rpc_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SKILL_NAME, "version": VERSION},
        })
    if method == "tools/list":
        return _rpc_result(rpc_id, {"tools": DEFINITIONS})
    if method == "tools/call":
        args = params.get("arguments")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            return _invalid(rpc_id, "arguments must be an object")
        name = params.get("name")
        if not isinstance(name, str):
            return _invalid(rpc_id, "name must be a string")
        if not tools.has(name):
            return _rpc_error(rpc_id, -32602, "unknown tool")
        return _rpc_result(rpc_id, await tools.call(name, args))
    return _rpc_error(rpc_id, -32601, "method not found")


def create_app(token: str, desktop: Desktop | None = None,
               workspace: str | None = None,
               browser: Browser | None = None) -> FastAPI:
    if not token:
        raise ValueError("LOOM_COMPUTER_TOKEN must be a non-empty token")
    desktop = desktop or Desktop()
    tools = Tools(guide, desktop,
                  workspace or os.environ.get("LOOM_WORKSPACE", WORKSPACE), browser)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        yield
        tools.shutdown()  # no job outlives the API

    app = FastAPI(title="Loom Computer", version=VERSION, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)

    hub = FrameHub(desktop)
    viewer_html, viewer_csp = _viewer_page()

    def token_ok(candidate: str | None) -> bool:
        return candidate is not None and hmac.compare_digest(
            candidate.encode("utf-8"), token.encode("utf-8"))

    def bearer_ok(request: Request) -> bool:
        scheme, _, presented = request.headers.get("authorization", "").partition(" ")
        return scheme.lower() == "bearer" and token_ok(presented.strip())

    @app.middleware("http")
    async def require_bearer(request: Request, call_next):
        # The contract leaves only the liveness probe and the viewer page
        # (whose token rides in the URL fragment) open; every other route and
        # method, known or not, answers the JSON 401 before routing.
        open_route = request.method in ("GET", "HEAD") and request.url.path in ("/health", "/")
        if not open_route and not bearer_ok(request):
            return JSONResponse(
                {"error": "unauthorized", "message": "valid bearer token required"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": VERSION}

    @app.post("/mcp")
    async def mcp(request: Request):
        # The holder is recognized and logged, nothing more.
        log.debug("mcp request holder=%s", request.headers.get("x-computer-holder"))
        try:
            message = await request.json()
        except ValueError:
            return JSONResponse(_rpc_error(None, -32700, "parse error"), status_code=400)
        if not isinstance(message, dict):
            return JSONResponse(
                _rpc_error(None, -32600, "invalid request: object required"),
                status_code=400)
        response = await _handle_rpc(message, tools)
        if response is None:
            return JSONResponse(None, status_code=202)
        invalid = response.get("error", {}).get("code") == INVALID_REQUEST
        return JSONResponse(response, status_code=400 if invalid else 200)

    @app.get("/files/download")
    async def download(path: str = "", max_bytes: str | None = None):
        """Raw bytes of one workspace file, for the desk. Same confinement
        as the `files` tool; `max_bytes` cuts the body short."""
        limit = None
        if max_bytes is not None:
            if not max_bytes.isascii() or not max_bytes.isdigit():
                return _download_error(400, "max_bytes must be a non-negative integer")
            limit = int(max_bytes)
        try:
            fd, size, _ = await tools.workspace.open_regular_async(path)
        except ToolError as exc:
            text = str(exc)
            if text == "no such file":
                return _download_error(404, "no such file")
            if "outside the workspace" in text:
                return _download_error(403, text)
            return _download_error(400, text)
        length = size if limit is None else min(size, limit)

        owned = _OwnedFd(fd)

        async def body():
            left = length
            while left > 0:
                chunk = await asyncio.to_thread(owned.read, min(65536, left))
                if not chunk:
                    break
                left -= len(chunk)
                yield chunk

        return _FdResponse(owned, body(), media_type="application/octet-stream", headers={
            "Content-Length": str(length), "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Loom-Truncated": "true" if length < size else "false"})

    @app.get("/", response_class=HTMLResponse)
    async def viewer():
        return HTMLResponse(viewer_html, headers={
            "Content-Security-Policy": viewer_csp,
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        })

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        # Accept first: closing before accept is an HTTP 403 handshake
        # rejection and the peer never sees a close code.
        await websocket.accept()
        if not token_ok(websocket.query_params.get("token")):
            await websocket.close(code=1008, reason="unauthorized")
            return
        queue = hub.subscribe()
        session: InputSession | None = None
        try:
            first = await queue.get()
            if isinstance(first, Exception):
                raise first
            width, height, _ = first
            await websocket.send_text(json.dumps(
                {"type": "hello", "width": width, "height": height}))
            session = InputSession(hub.desktop, width, height)
            sender = asyncio.create_task(_send_frames(websocket, queue, first))
            receiver = asyncio.create_task(_receive_input(websocket, session))
            done, pending = await asyncio.wait(
                {sender, receiver}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for outcome in await asyncio.gather(*done, return_exceptions=True):
                if isinstance(outcome, Exception) and not isinstance(
                        outcome, WebSocketDisconnect):
                    raise outcome
        except WebSocketDisconnect:
            pass
        except Exception:  # noqa: BLE001
            log.exception("viewer socket failed")
            try:
                await websocket.close(code=1011, reason="desktop unavailable")
            except RuntimeError:
                pass
        finally:
            hub.unsubscribe(queue)
            if session is not None:
                await session.release_all()

    return app


async def _send_frames(websocket: WebSocket, queue: asyncio.Queue, first) -> None:
    """Frames go out as binary JPEG messages, newest only."""
    item = first
    while True:
        if isinstance(item, Exception):
            raise item
        await websocket.send_bytes(item[2])
        item = await queue.get()


async def _receive_input(websocket: WebSocket, session: InputSession) -> None:
    """Text messages in are JSON input events; binary ones are refused."""
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            raise WebSocketDisconnect(message.get("code", 1000))
        if message.get("bytes") is not None:
            await websocket.close(code=1003, reason="text only")
            return
        try:
            event = json.loads(message.get("text") or "")
        except ValueError:
            continue
        await session.handle(event)


_TOKEN_QUERY = re.compile(r"([?&]token=)[^&\s\"']*")


class _RedactToken(logging.Filter):
    """Keeps `?token=` values out of every record uvicorn emits.

    Uvicorn logs the websocket request target, query string included, at INFO.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if "token=" in message:
            record.msg, record.args = _TOKEN_QUERY.sub(r"\1REDACTED", message), ()
        return True


def log_config() -> dict:
    """Uvicorn's logging config with token redaction on every handler."""
    from uvicorn.config import LOGGING_CONFIG

    config = copy.deepcopy(LOGGING_CONFIG)
    config["filters"] = {"redact_token": {"()": _RedactToken}}
    for handler in config["handlers"].values():
        handler["filters"] = ["redact_token"]
    return config


def main() -> None:
    import uvicorn

    logging.basicConfig(level=os.environ.get("LOOM_COMPUTER_LOG", "INFO").upper())
    token = os.environ.get("LOOM_COMPUTER_TOKEN", "")
    if not token:
        sys.exit("loom-computer: LOOM_COMPUTER_TOKEN is not set; refusing to start "
                 "(every /mcp call needs a bearer token)")
    uvicorn.run(create_app(token), host="0.0.0.0", port=PORT, log_level="info",
                access_log=False, log_config=log_config())
