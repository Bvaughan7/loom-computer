"""HTTP surface of the computer: /health, /mcp, /, /ws."""

import copy
import hashlib
import hmac
import json
import logging
import os
import re
import sys
from importlib import resources

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse

from . import VERSION

PORT = 8787
SKILL_NAME = "loom-computer"
log = logging.getLogger("loom_computer")

VIEWER_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Loom Computer</title></head>
<body>
<h1>Loom Computer</h1>
<p>The viewer lands in Phase 1.</p>
</body>
</html>
"""


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


def _not_implemented(rpc_id) -> dict:
    return _rpc_error(rpc_id, -32601, "not implemented")


def _invalid(rpc_id, why: str) -> dict:
    return _rpc_error(rpc_id, INVALID_REQUEST, f"invalid request: {why}")


STATE_TOOL = {
    "name": "state",
    "description": "Computer state and the release guide.",
    "inputSchema": {
        "type": "object",
        "properties": {"action": {"type": "string", "enum": ["guide"]}},
        "required": ["action"],
    },
}


def _handle_rpc(message: dict) -> dict | None:
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
        return _rpc_result(rpc_id, {"tools": [STATE_TOOL]})
    if method == "tools/call":
        args = params.get("arguments")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            return _invalid(rpc_id, "arguments must be an object")
        if params.get("name") == "state" and args.get("action") == "guide":
            body = guide()
            return _rpc_result(rpc_id, {
                "content": [{"type": "text", "text": json.dumps(body)}],
                "structuredContent": body,
                "isError": False,
            })
    return _not_implemented(rpc_id)


def create_app(token: str) -> FastAPI:
    if not token:
        raise ValueError("LOOM_COMPUTER_TOKEN must be a non-empty token")
    app = FastAPI(title="Loom Computer", version=VERSION,
                  docs_url=None, redoc_url=None, openapi_url=None)

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
        # Phase 0: the holder is recognized and logged, nothing more.
        log.debug("mcp request holder=%s", request.headers.get("x-computer-holder"))
        try:
            message = await request.json()
        except ValueError:
            return JSONResponse(_rpc_error(None, -32700, "parse error"), status_code=400)
        if not isinstance(message, dict):
            return JSONResponse(
                _rpc_error(None, -32600, "invalid request: object required"),
                status_code=400)
        response = _handle_rpc(message)
        if response is None:
            return JSONResponse(None, status_code=202)
        invalid = response.get("error", {}).get("code") == INVALID_REQUEST
        return JSONResponse(response, status_code=400 if invalid else 200)

    @app.get("/", response_class=HTMLResponse)
    async def viewer():
        return VIEWER_HTML

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        # Accept first: closing before accept is an HTTP 403 handshake
        # rejection and the peer never sees a close code.
        await websocket.accept()
        if not token_ok(websocket.query_params.get("token")):
            await websocket.close(code=1008, reason="unauthorized")
            return
        await websocket.send_text(json.dumps(
            {"error": "not_implemented", "message": "the viewer socket lands in Phase 1"}))
        await websocket.close(code=1013, reason="not implemented")

    return app


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
