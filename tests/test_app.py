import hashlib
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from loom_computer import VERSION
from loom_computer.app import create_app

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
    assert guide["checksum"] == "sha256:" + hashlib.sha256(
        guide["content"].encode()).hexdigest()


def test_other_calls_not_implemented(client):
    r = rpc(client, "tools/call", {"name": "shell", "arguments": {}})
    assert r.json()["error"]["message"].startswith("not implemented")


def test_viewer_placeholder(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Phase 1" in r.text


def test_ws_rejects_bad_token(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws?token=bad"):
            pass


def test_ws_valid_token_closes_not_implemented(client):
    with client.websocket_connect(f"/ws?token={TOKEN}") as ws:
        assert ws.receive_json()["error"] == "not_implemented"
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()


def test_startup_fails_without_token():
    r = subprocess.run([sys.executable, "-m", "loom_computer"], capture_output=True,
                       text=True, env={"PATH": ""})
    assert r.returncode != 0
    assert "LOOM_COMPUTER_TOKEN" in r.stderr
