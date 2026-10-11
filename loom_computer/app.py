"""HTTP surface of the computer: /health, /mcp, /, /ws."""

import hashlib
import hmac
import json
import logging
import os
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
    """The release's own skill with its version and checksum."""
    document = _skill_document()
    return {
        "name": SKILL_NAME,
        "version": VERSION,
        "checksum": "sha256:" + hashlib.sha256(document.encode("utf-8")).hexdigest(),
        "content": document,
    }


def _rpc_result(rpc_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _rpc_error(rpc_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


def _not_implemented(rpc_id, what: str) -> dict:
    return _rpc_error(rpc_id, -32601, f"not implemented: {what}")


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
    rpc_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}

    if method is None:
        return _rpc_error(rpc_id, -32600, "invalid request: method required")
    if rpc_id is None:  # notification: no response
        return None
    if method == "initialize":
        return _rpc_result(rpc_id, {
            "protocolVersion": params.get("protocolVersion", "2025-03-26"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SKILL_NAME, "version": VERSION},
        })
    if method == "tools/list":
        return _rpc_result(rpc_id, {"tools": [STATE_TOOL]})
    if method == "tools/call":
        tool = params.get("name")
        args = params.get("arguments") or {}
        if tool == "state" and args.get("action") == "guide":
            body = guide()
            return _rpc_result(rpc_id, {
                "content": [{"type": "text", "text": json.dumps(body)}],
                "structuredContent": body,
                "isError": False,
            })
        return _not_implemented(rpc_id, f"tool {tool!r} action {args.get('action')!r}")
    return _not_implemented(rpc_id, f"method {method!r}")


def create_app(token: str) -> FastAPI:
    if not token:
        raise ValueError("LOOM_COMPUTER_TOKEN must be a non-empty token")
    app = FastAPI(title="Loom Computer", version=VERSION,
                  docs_url=None, redoc_url=None, openapi_url=None)

    def token_ok(candidate: str | None) -> bool:
        return candidate is not None and hmac.compare_digest(
            candidate.encode("utf-8"), token.encode("utf-8"))

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": VERSION}

    @app.post("/mcp")
    async def mcp(request: Request):
        header = request.headers.get("authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer" or not token_ok(presented.strip()):
            return JSONResponse(
                {"error": "unauthorized", "message": "valid bearer token required"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
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
        return JSONResponse(response)

    @app.get("/", response_class=HTMLResponse)
    async def viewer():
        return VIEWER_HTML

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        if not token_ok(websocket.query_params.get("token")):
            await websocket.close(code=1008, reason="unauthorized")
            return
        await websocket.accept()
        await websocket.send_text(json.dumps(
            {"error": "not_implemented", "message": "the viewer socket lands in Phase 1"}))
        await websocket.close(code=1013, reason="not implemented")

    return app


def main() -> None:
    import uvicorn

    logging.basicConfig(level=os.environ.get("LOOM_COMPUTER_LOG", "INFO").upper())
    token = os.environ.get("LOOM_COMPUTER_TOKEN", "")
    if not token:
        sys.exit("loom-computer: LOOM_COMPUTER_TOKEN is not set; refusing to start "
                 "(every /mcp call needs a bearer token)")
    uvicorn.run(create_app(token), host="0.0.0.0", port=PORT, log_level="info")
