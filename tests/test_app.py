import hashlib
import io
import json
import logging.config
import re
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from loom_computer import VERSION
from loom_computer.app import create_app, log_config

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def client():
    return TestClient(create_app(TOKEN))


def rpc(client, method, params=None, headers=AUTH, id=1):
    body = {"jsonrpc": "2.0", "id": id, "method": method}
    if params is not None:
        body["params"] = params
    return client.post("/mcp", json=body, headers=headers)


def test_health_open(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_mcp_requires_bearer(client):
    r = rpc(client, "tools/list", headers={})
    assert r.status_code == 401
    assert r.json()["error"] == "unauthorized"


def test_mcp_rejects_wrong_bearer(client):
    r = rpc(client, "tools/list", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_mcp_valid_bearer_not_401(client):
    r = rpc(client, "tools/list")
    assert r.status_code == 200


def test_guide_returns_name_version_checksum(client):
    r = rpc(client, "tools/call", {"name": "state", "arguments": {"action": "guide"}},
            headers={**AUTH, "X-Computer-Holder": "persona-1"})
    assert r.status_code == 200
    guide = r.json()["result"]["structuredContent"]
    assert guide["name"] == "loom-computer"
    assert guide["version"] == VERSION == "0.10.3"
    assert guide["sha256"] == hashlib.sha256(guide["skill"].encode()).hexdigest()
    assert "checksum" not in guide and "content" not in guide


def test_guide_matches_loom_parser_manifest(client):
    # Loom's guide parser reads the first text block as JSON and needs string
    # `version`, `sha256` (64 bare hex) and `skill`.
    r = rpc(client, "tools/call", {"name": "state", "arguments": {"action": "guide"}})
    manifest = json.loads(r.json()["result"]["content"][0]["text"])
    for field in ("version", "sha256", "skill"):
        assert isinstance(manifest[field], str) and manifest[field]
    assert re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"])


def test_other_calls_not_implemented(client):
    r = rpc(client, "tools/call", {"name": "shell", "arguments": {}})
    assert r.json()["error"]["message"].startswith("not implemented")


def test_ws_rejects_bad_token_with_1008(client):
    with client.websocket_connect("/ws?token=bad") as ws:
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_text()
    assert closed.value.code == 1008


@pytest.mark.parametrize("method", ["get", "delete", "put", "patch", "post"])
@pytest.mark.parametrize("path", ["/mcp", "/secrets", "/logins/x", "/nope"])
def test_every_method_and_route_needs_bearer(client, method, path):
    r = client.request(method, path)
    assert r.status_code == 401
    assert r.json()["error"] == "unauthorized"
    assert r.headers["www-authenticate"] == "Bearer"


def test_open_routes_stay_open(client):
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200


def test_get_mcp_with_bearer_is_not_401(client):
    assert client.get("/mcp", headers=AUTH).status_code == 405


@pytest.mark.parametrize("message", [
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "x"},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "state", "arguments": ["guide"]}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "state", "arguments": "guide"}},
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 5}},
    {"jsonrpc": "1.0", "id": 1, "method": "tools/list"},
    {"id": 1, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 1, "method": 7},
    {"jsonrpc": "2.0", "id": 1},
    {"jsonrpc": "2.0", "id": {"a": 1}, "method": "tools/list"},
])
def test_malformed_rpc_is_invalid_request_not_500(client, message):
    r = client.post("/mcp", json=message, headers=AUTH)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32600


def test_missing_id_is_notification_null_id_is_request(client):
    base = {"jsonrpc": "2.0", "method": "tools/list"}
    assert client.post("/mcp", json=base, headers=AUTH).status_code == 202
    r = client.post("/mcp", json={**base, "id": None}, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["id"] is None and "tools" in body["result"]


def test_errors_do_not_reflect_input(client):
    probe = "ZZ-reflect-probe"
    cases = [
        ("tools/call", {"name": probe, "arguments": {"action": probe}}),
        (probe, {}),
        ("tools/call", {"name": "state", "arguments": [probe]}),
    ]
    for method, params in cases:
        r = rpc(client, method, params)
        assert probe not in r.text
    r = client.post("/mcp", json={"jsonrpc": probe, "id": 1, "method": "x"}, headers=AUTH)
    assert probe not in r.text


def test_token_is_redacted_from_uvicorn_logs(monkeypatch):
    stream = io.StringIO()
    monkeypatch.setattr("sys.stderr", stream)
    logging.config.dictConfig(log_config())
    try:
        logging.getLogger("uvicorn.error").info(
            '%s - "WebSocket %s" [accepted]', ("127.0.0.1", 1), "/ws?token=s3cret&x=1")
        logging.getLogger("uvicorn.access").info(
            '%s - "%s %s HTTP/%s" %d', "127.0.0.1:1", "GET", "/ws?token=s3cret", "1.1", 200)
    finally:
        logging.config.dictConfig(
            {"version": 1, "disable_existing_loggers": False})
    out = stream.getvalue()
    assert "s3cret" not in out
    assert "/ws?token=REDACTED" in out


def test_startup_fails_without_token():
    r = subprocess.run([sys.executable, "-m", "loom_computer"], capture_output=True,
                       text=True, env={"PATH": ""})
    assert r.returncode != 0
    assert "LOOM_COMPUTER_TOKEN" in r.stderr
