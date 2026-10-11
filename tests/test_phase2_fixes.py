"""Regression tests for the Phase 2 review findings and the download door."""

import asyncio
import http.server
import json
import os
import threading
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from websockets.asyncio.server import serve

from loom_computer.app import create_app
from loom_computer.browser import MAX_TREE_BYTES, Browser, render_tree
from loom_computer.errors import ToolError
from loom_computer.tools import Tools
from loom_computer.workspace import Workspace

from test_tools import AUTH, answer, call, refusal


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    return root


@pytest.fixture
def client(workspace):
    return TestClient(create_app("tools-token", workspace=str(workspace),
                                 browser=Browser("http://127.0.0.1:1")))


# -- 1. TOCTOU ----------------------------------------------------------------

def swap_for_link(ws: Workspace, directory, target):
    """Make the next `resolve` hand back a path, then replace `directory`
    with a symlink to `target` before the caller opens it."""
    real_resolve = ws.resolve

    def resolve(path):
        real = real_resolve(path)
        directory.rename(str(directory) + ".moved")
        directory.symlink_to(target)
        return real
    ws.resolve = resolve


def test_read_refuses_a_directory_swapped_for_a_symlink(workspace, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "f.txt").write_text("secret")
    (workspace / "d").mkdir()
    (workspace / "d" / "f.txt").write_text("inside")
    ws = Workspace(str(workspace))
    swap_for_link(ws, workspace / "d", outside)
    with pytest.raises(ToolError, match="symlink"):
        ws.read("d/f.txt")


def test_write_refuses_a_directory_swapped_for_a_symlink(workspace, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "d").mkdir()
    ws = Workspace(str(workspace))
    swap_for_link(ws, workspace / "d", outside)
    with pytest.raises(ToolError):
        ws.write("d/new.txt", "pwned")
    assert list(outside.iterdir()) == []


def test_write_does_not_follow_a_final_symlink_swapped_in(workspace, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("keep")
    ws = Workspace(str(workspace))
    real_resolve = ws.resolve

    def resolve(path):
        real = real_resolve(path)
        os.symlink(secret, real)  # appears after the check
        return real
    ws.resolve = resolve
    with pytest.raises(ToolError):
        ws.write("t.txt", "pwned")
    assert secret.read_text() == "keep"


def test_files_run_executes_the_checked_file_not_a_swapped_one(workspace, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "s.sh").write_text("echo escaped\n")
    (workspace / "d").mkdir()
    (workspace / "d" / "s.sh").write_text("echo inside\n")
    tools = Tools(lambda: {}, SimpleNamespace(display=":0"), str(workspace))
    swap_for_link(tools.workspace, workspace / "d", outside)
    result = asyncio.run(tools.call("files", {"action": "run", "path": "d/s.sh"}))
    assert result["isError"] is True  # refused; "escaped" never ran
    assert "escaped" not in json.dumps(result)


def test_files_run_still_runs_a_script_in_place(client, workspace):
    (workspace / "s.sh").write_text("echo ok $1\n")
    r = answer(call(client, "files", {"action": "run", "path": "s.sh", "args": ["x"]}))
    assert r["stdout"] == "ok x\n"


# -- 3. unexpected exceptions are isError, not 500 -----------------------------

def test_unexpected_handler_exception_is_an_error_result(client, monkeypatch):
    async def boom(_args):
        raise KeyError("text")
    monkeypatch.setattr(Tools, "_shell", lambda self, a: boom(a))
    text = refusal(call(client, "shell", {"command": "true"}))
    assert text.startswith("shell: unexpected KeyError")


# -- 4. lone surrogate ---------------------------------------------------------

def raw_call(client, name, arguments_json: str):
    """tools/call with hand-written JSON (the client cannot encode surrogates)."""
    body = ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s",'
            '"arguments":%s}}' % (name, arguments_json))
    r = client.post("/mcp", content=body, headers={**AUTH, "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    return r.json()["result"]


def test_lone_surrogate_content_is_a_refusal(client, workspace):
    text = refusal(raw_call(client, "files", json.dumps(
        {"action": "write", "path": "s.txt", "content": "a@@b"}).replace("@@", "\\ud800")))
    assert "surrogate" in text
    assert not (workspace / "s.txt").exists()


def test_lone_surrogate_path_is_a_refusal(client):
    text = refusal(raw_call(client, "files", json.dumps(
        {"action": "read", "path": "a@@"}).replace("@@", "\\udc80")))
    assert "valid Unicode" in text


# -- 6. listing limit ----------------------------------------------------------

def test_list_stops_at_the_limit_while_iterating(workspace, monkeypatch):
    import loom_computer.workspace as w
    monkeypatch.setattr(w, "MAX_ENTRIES", 5)
    for i in range(12):
        (workspace / f"f{i:02}").write_text("")
    out = Workspace(str(workspace)).list(".")
    assert len(out["entries"]) == 5 and out["truncated"] is True
    names = [e["name"] for e in out["entries"]]
    assert names == sorted(names)


# -- 5. tree byte cap ----------------------------------------------------------

def test_tree_is_capped_in_bytes_and_clips_huge_names():
    huge = "x" * 5_000_000
    nodes = [{"nodeId": "1", "role": {"value": "RootWebArea"}, "name": {"value": "T"},
              "childIds": [str(i) for i in range(2, 600)]}]
    for i in range(2, 600):
        nodes.append({"nodeId": str(i), "role": {"value": "paragraph"},
                      "name": {"value": huge}, "value": {"value": huge}})
    out = render_tree("T", "u", nodes)
    assert len(out.encode()) < MAX_TREE_BYTES + 200
    assert "tree cut" in out
    assert huge not in out


def test_tree_clips_one_huge_node_even_under_the_line_cap():
    nodes = [{"nodeId": "1", "role": {"value": "RootWebArea"}, "name": {"value": "y" * 10**6}}]
    assert len(render_tree("t" * 10**6, "u" * 10**6, nodes)) < 5_000


# -- 2 & 3. fake CDP: active tab, SVG text -------------------------------------

class FakeChromium:
    def __init__(self, tabs):
        self.tabs = tabs  # list of dicts: title, visible, focus, text
        self._ready = threading.Event()

    def start(self):
        threading.Thread(target=self._run_ws, daemon=True).start()
        self._ready.wait(5)
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps([
                    {"type": "page", "url": f"https://t{i}.test/", "title": t["title"],
                     "webSocketDebuggerUrl": f"ws://127.0.0.1:{fake.ws_port}/{i}"}
                    for i, t in enumerate(fake.tabs)]).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.http.server_address[1]}"

    def stop(self):
        self.http.shutdown()
        self.loop.call_soon_threadsafe(self.stop_event.set)

    def _run_ws(self):
        async def main():
            self.loop = asyncio.get_running_loop()
            self.stop_event = asyncio.Event()
            async with serve(self._handle, "127.0.0.1", 0) as server:
                self.ws_port = server.sockets[0].getsockname()[1]
                self._ready.set()
                await self.stop_event.wait()
        asyncio.run(main())

    async def _handle(self, socket):
        tab = self.tabs[int(socket.request.path.strip("/"))]
        async for raw in socket:
            msg = json.loads(raw)
            expression = msg.get("params", {}).get("expression", "")
            if "visibilityState" in expression:
                value = ["visible" if tab["visible"] else "hidden", tab["focus"]]
            elif "document.title" in expression:
                value = tab["title"]
            elif "location.href" in expression:
                value = "https://x.test/"
            elif "innerText" in expression:
                value = tab["text"]
            else:
                value = None
            await socket.send(json.dumps({"id": msg["id"],
                                          "result": {"result": {"value": value}}}))


@pytest.fixture
def chromium():
    started = []

    def make(tabs):
        fake = FakeChromium(tabs)
        started.append(fake)
        return fake, Browser(fake.start())
    yield make
    for fake in started:
        fake.stop()


def test_browser_acts_on_the_active_tab_not_the_first(chromium):
    _, browser = chromium([
        {"title": "first", "visible": False, "focus": False, "text": {}},
        {"title": "second", "visible": True, "focus": False, "text": {}},
        {"title": "active", "visible": True, "focus": True, "text": {}},
    ])
    assert asyncio.run(browser.title())["title"] == "active"


def test_browser_prefers_a_visible_tab_when_none_is_focused(chromium):
    _, browser = chromium([
        {"title": "hidden", "visible": False, "focus": False, "text": {}},
        {"title": "shown", "visible": True, "focus": False, "text": {}},
    ])
    assert asyncio.run(browser.title())["title"] == "shown"


def test_browser_falls_back_to_the_first_tab_when_none_reports_visible(chromium):
    _, browser = chromium([
        {"title": "one", "visible": False, "focus": False, "text": {}},
        {"title": "two", "visible": False, "focus": False, "text": {}},
    ])
    assert asyncio.run(browser.title())["title"] == "one"


def test_browser_text_of_an_svg_element_is_empty_not_an_error(chromium):
    _, browser = chromium([{"title": "svg", "visible": True, "focus": True, "text": {}}])
    assert asyncio.run(browser.text("svg")) == {"text": "", "truncated": False}


def test_browser_text_over_http_never_500s(chromium, workspace):
    fake, browser = chromium([{"title": "svg", "visible": True, "focus": True, "text": {}}])
    c = TestClient(create_app("tools-token", workspace=str(workspace), browser=browser))
    assert answer(call(c, "browser", {"action": "text", "selector": "svg"}))["text"] == ""


# -- 7. GET /files/download ----------------------------------------------------

def test_download_requires_bearer(client, workspace):
    (workspace / "a.txt").write_text("hi")
    r = client.get("/files/download", params={"path": "a.txt"})
    assert r.status_code == 401 and r.json()["error"] == "unauthorized"
    r = client.get("/files/download", params={"path": "a.txt"},
                   headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_download_streams_the_bytes(client, workspace):
    blob = bytes(range(256)) * 1000
    (workspace / "sub").mkdir()
    (workspace / "sub" / "b.bin").write_bytes(blob)
    r = client.get("/files/download", params={"path": "sub/b.bin"}, headers=AUTH)
    assert r.status_code == 200 and r.content == blob
    assert r.headers["content-type"] == "application/octet-stream"
    absolute = client.get("/files/download", headers=AUTH,
                          params={"path": str(workspace / "sub" / "b.bin")})
    assert absolute.content == blob


def test_download_honors_max_bytes(client, workspace):
    (workspace / "a.txt").write_text("0123456789")
    r = client.get("/files/download", params={"path": "a.txt", "max_bytes": "4"}, headers=AUTH)
    assert r.content == b"0123" and r.headers["x-loom-truncated"] == "true"
    r = client.get("/files/download", params={"path": "a.txt", "max_bytes": "100"}, headers=AUTH)
    assert r.content == b"0123456789" and r.headers["x-loom-truncated"] == "false"
    r = client.get("/files/download", params={"path": "a.txt", "max_bytes": "-1"}, headers=AUTH)
    assert r.status_code == 400


def test_download_missing_is_404(client):
    r = client.get("/files/download", params={"path": "nope.txt"}, headers=AUTH)
    assert r.status_code == 404 and r.json()["error"] == "download_failed"


@pytest.mark.parametrize("path", ["../outside.txt", "a/../../outside.txt",
                                  "/etc/passwd", "..", "/"])
def test_download_refuses_traversal(client, workspace, tmp_path, path):
    (tmp_path / "outside.txt").write_text("secret")
    r = client.get("/files/download", params={"path": path}, headers=AUTH)
    assert r.status_code in (403, 400) and b"secret" not in r.content
    assert r.status_code == 403 or path in ("/",)


def test_download_refuses_symlink_out_and_directories(client, workspace, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    (workspace / "link").symlink_to(secret)
    (workspace / "dirlink").symlink_to(tmp_path)
    (workspace / "d").mkdir()
    for path in ("link", "dirlink/secret.txt"):
        r = client.get("/files/download", params={"path": path}, headers=AUTH)
        assert r.status_code == 403 and b"top secret" not in r.content
    assert client.get("/files/download", params={"path": "d"}, headers=AUTH).status_code == 400
    assert client.get("/files/download", headers=AUTH).status_code == 400
