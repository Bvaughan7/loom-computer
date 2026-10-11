"""Viewer page, /ws auth and input, driven by a fake desktop (no X needed)."""

import json
import re

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from loom_computer.app import create_app
from loom_computer.desktop import keysym_for

TOKEN = "test-token"
JPEG = b"\xff\xd8fake-frame\xff\xd9"


class FakeDesktop:
    """Stands in for Desktop: one fixed frame, input recorded."""

    def __init__(self, fail=False):
        self.fail, self.calls = fail, []

    async def frame(self):
        if self.fail:
            raise RuntimeError("no display")
        return 640, 480, JPEG, b"d" * 16

    async def key_down(self, keysym):
        self.calls.append(("key_down", keysym))
        return keysym + 1000

    async def key_up(self, keycode):
        self.calls.append(("key_up", keycode))

    async def button(self, number, down):
        self.calls.append(("button", number, down))

    async def move(self, x, y):
        self.calls.append(("move", x, y))


@pytest.fixture
def desktop():
    return FakeDesktop()


@pytest.fixture
def client(desktop):
    return TestClient(create_app(TOKEN, desktop=desktop))


def test_viewer_serves_real_page(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "<canvas" in r.text and "location.hash" in r.text
    assert "Phase 1" not in r.text


def test_viewer_never_puts_token_in_a_request_line(client):
    page = client.get("/").text
    # The only place the page builds a /ws URL is from the fragment-read token.
    assert "location.hash" in page
    assert "?token=" in page and TOKEN not in page


def test_viewer_csp_pins_inline_script(client):
    csp = client.get("/").headers["content-security-policy"]
    assert re.search(r"script-src 'sha256-[A-Za-z0-9+/=]+'", csp)
    assert "unsafe-inline" not in csp and "default-src 'none'" in csp


def test_ws_without_token_is_closed_1008(client):
    with client.websocket_connect("/ws") as ws:
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_text()
    assert closed.value.code == 1008


def test_ws_with_wrong_token_is_closed_1008(client):
    with client.websocket_connect("/ws?token=nope") as ws:
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_text()
    assert closed.value.code == 1008


def test_ws_valid_token_sends_hello_then_frame(client):
    with client.websocket_connect(f"/ws?token={TOKEN}") as ws:
        assert ws.receive_json() == {"type": "hello", "width": 640, "height": 480}
        assert ws.receive_bytes() == JPEG


def test_ws_input_reaches_desktop_and_is_released_on_close(client, desktop):
    with client.websocket_connect(f"/ws?token={TOKEN}") as ws:
        ws.receive_json(), ws.receive_bytes()
        ws.send_text(json.dumps({"t": "pointer", "x": 10, "y": 20, "buttons": 1}))
        ws.send_text(json.dumps({"t": "key", "key": "a", "down": True}))
        ws.send_text("not json")
        ws.send_text(json.dumps({"t": "pointer", "x": "evil", "y": 1, "buttons": 0}))
        ws.send_text(json.dumps({"t": "wheel", "dy": 1}))
        ws.send_text(json.dumps({"t": "pointer", "x": 99999, "y": -5, "buttons": 1}))
    # Closing releases the held key; the button was still down.
    assert ("move", 10, 20) in desktop.calls
    assert ("button", 1, True) in desktop.calls
    assert ("key_down", ord("a")) in desktop.calls
    assert ("button", 5, True) in desktop.calls and ("button", 5, False) in desktop.calls
    assert ("move", 639, 0) in desktop.calls      # clamped to the screen
    assert ("move", 0, 0) not in desktop.calls and all(
        c != ("move", "evil", 1) for c in desktop.calls)
    assert desktop.calls[-2:] == [("button", 1, False), ("key_up", ord("a") + 1000)]


def test_ws_binary_from_viewer_is_refused(client):
    with client.websocket_connect(f"/ws?token={TOKEN}") as ws:
        ws.receive_json(), ws.receive_bytes()
        ws.send_bytes(b"\x00")
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_text()
    assert closed.value.code == 1003


def test_ws_without_display_closes_1011():
    client = TestClient(create_app(TOKEN, desktop=FakeDesktop(fail=True)))
    with client.websocket_connect(f"/ws?token={TOKEN}") as ws:
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_text()
    assert closed.value.code == 1011


@pytest.mark.parametrize("key,keysym", [
    ("a", 0x61), ("A", 0x41), ("Enter", 0xFF0D), ("F5", 0xFFC2),
    ("é", 0xE9), ("€", 0x010020AC),
])
def test_keysyms(key, keysym):
    assert keysym_for(key) == keysym


@pytest.mark.parametrize("key", ["", "Dead", None, 5, "Unidentified"])
def test_unmapped_keys(key):
    assert keysym_for(key) is None
