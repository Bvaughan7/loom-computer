"""The MCP tools, end to end through POST /mcp. Everything runs for real: real
subprocesses, a real workspace directory, and (with Xvfb) a real screen.
The browser is covered against the built image in test_image.py."""

import base64
import io
import json
import os
import shutil
import time

import pytest
from fastapi.testclient import TestClient

from loom_computer.app import create_app
from loom_computer.browser import Browser, render_tree
from loom_computer.desktop import Desktop

TOKEN = "tools-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
needs_xvfb = pytest.mark.skipif(shutil.which("Xvfb") is None, reason="Xvfb not installed")


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    return root


@pytest.fixture
def client(workspace):
    # No Chromium here: point the browser at a port nobody listens on.
    return TestClient(create_app(TOKEN, workspace=str(workspace),
                                 browser=Browser("http://127.0.0.1:1")))


def call(client, name, arguments=None, headers=AUTH):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}}}
    r = client.post("/mcp", json=body, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["result"]


def answer(result):
    """The JSON a tool answered in its first text block."""
    assert result["isError"] is False, result
    return json.loads(result["content"][0]["text"])


def refusal(result) -> str:
    assert result["isError"] is True, result
    return result["content"][0]["text"]


# -- auth and listing ---------------------------------------------------------

def test_tools_call_without_bearer_is_401(client):
    for name, args in (("shell", {"command": "echo hi"}), ("files", {"action": "list"}),
                       ("capture", {"mode": "image"}), ("state", {"action": "guide"})):
        r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": {"name": name, "arguments": args}})
        assert r.status_code == 401
        assert r.json()["error"] == "unauthorized"


def test_tools_list_names(client):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers=AUTH)
    tools = {t["name"]: t for t in r.json()["result"]["tools"]}
    assert set(tools) == {"state", "shell", "files", "browser", "capture"}
    assert all(t["inputSchema"]["type"] == "object" for t in tools.values())


def test_unknown_tool_is_a_protocol_error(client):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": "nope", "arguments": {}}}, headers=AUTH)
    assert r.json()["error"]["code"] == -32602


# -- state --------------------------------------------------------------------

def test_state_guide_documents_the_tools(client):
    guide = call(client, "state", {"action": "guide"})["structuredContent"]
    assert set(guide) >= {"version", "sha256", "skill"}
    for word in ("shell", "files", "browser", "capture", "fill", "region"):
        assert word in guide["skill"]
    assert "Phase 0" not in guide["skill"]


@pytest.mark.parametrize("action", ["login_load", "nonsense", ""])
def test_state_unknown_action_error_string(client, action):
    r = call(client, "state", {"action": action, "name": "x"})
    assert refusal(r) == f"state: unknown action {action}"


# -- shell --------------------------------------------------------------------

def test_shell_echo(client):
    r = answer(call(client, "shell", {"command": "echo hello"}))
    assert r["stdout"] == "hello\n"
    assert r["stderr"] == "" and r["exit_code"] == 0 and r["timed_out"] is False


def test_shell_reports_exit_code_and_stderr(client):
    r = call(client, "shell", {"command": "echo oops >&2; exit 3"})
    out = answer(r)  # a command that ran is an answer, not an error
    assert out["exit_code"] == 3 and out["stderr"] == "oops\n"


def test_shell_default_cwd_is_the_workspace_and_cwd_overrides(client, workspace):
    (workspace / "sub").mkdir()
    assert answer(call(client, "shell", {"command": "pwd"}))["stdout"].strip() == str(workspace)
    r = answer(call(client, "shell", {"command": "pwd", "cwd": "sub"}))
    assert r["stdout"].strip() == str(workspace / "sub")
    assert "not a directory" in refusal(call(client, "shell", {"command": "pwd", "cwd": "nope"}))


def test_shell_argv_is_not_interpreted_by_a_shell(client, workspace):
    r = answer(call(client, "shell", {"argv": ["echo", "$HOME", ";", "touch", "pwned"]}))
    assert r["stdout"] == "$HOME ; touch pwned\n"
    assert not (workspace / "pwned").exists()


@pytest.mark.parametrize("args", [
    {}, {"command": "echo", "argv": ["echo"]}, {"argv": []}, {"argv": [1]},
    {"command": 5}, {"command": "echo", "timeout": -1}, {"command": "echo", "bogus": 1},
])
def test_shell_rejects_bad_arguments(client, args):
    assert refusal(call(client, "shell", args)).startswith("shell: ")


def test_shell_missing_program_is_a_refusal(client):
    assert "no such file or command" in refusal(call(client, "shell", {"argv": ["no-such-prog"]}))


def test_shell_timeout_kills_the_whole_tree(client, workspace):
    started = time.monotonic()
    r = answer(call(client, "shell", {
        "command": "sleep 60 & echo $! > child.pid; wait", "timeout": 1}))
    assert r["timed_out"] is True and r["exit_code"] is None
    assert time.monotonic() - started < 10
    pid = int((workspace / "child.pid").read_text())
    for _ in range(40):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail("a background child of the job survived its timeout")


def test_shell_leftovers_are_killed_when_the_command_exits(client, workspace):
    answer(call(client, "shell", {"command": "sleep 60 & echo $! > child.pid"}))
    pid = int((workspace / "child.pid").read_text())
    for _ in range(40):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    pytest.fail("a leftover process outlived the call")


def test_shell_output_is_bounded_keeping_both_ends(client):
    r = answer(call(client, "shell", {
        "command": "echo START; head -c 2000000 /dev/zero | tr '\\0' x; echo; echo END"}))
    assert r["truncated"] is True
    assert r["stdout"].startswith("START\n") and r["stdout"].rstrip().endswith("END")
    assert len(r["stdout"]) < 300_000 and "bytes omitted" in r["stdout"]


def test_jobs_do_not_inherit_the_servers_environment(client, workspace, monkeypatch):
    monkeypatch.setenv("LOOM_COMPUTER_TOKEN", "hunter2-secret")
    monkeypatch.setenv("SERVER_ONLY", "leak")
    (workspace / ".loom").mkdir()
    (workspace / ".loom" / "env").write_text(
        "# comment\nGREETING='hi there'\nexport PLAIN=1\nLOOM_COMPUTER_TOKEN=evil\nbad name=1\n")
    out = answer(call(client, "shell", {"command": "env"}))["stdout"]
    env = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    assert env["GREETING"] == "hi there" and env["PLAIN"] == "1"
    assert "LOOM_COMPUTER_TOKEN" not in env and "SERVER_ONLY" not in env
    assert "hunter2-secret" not in out and "evil" not in out


# -- files --------------------------------------------------------------------

def test_files_write_then_read_round_trips(client, workspace):
    w = answer(call(client, "files", {"action": "write", "path": "notes/a.txt",
                                      "content": "héllo\nworld"}))
    assert w["path"] == "notes/a.txt"
    assert (workspace / "notes" / "a.txt").read_text() == "héllo\nworld"
    r = answer(call(client, "files", {"action": "read", "path": "notes/a.txt"}))
    assert r["content"] == "héllo\nworld"
    assert r["bytes"] == len("héllo\nworld".encode())


def test_files_base64_append_and_list(client):
    blob = bytes(range(256))
    call(client, "files", {"action": "write", "path": "b.bin", "encoding": "base64",
                           "content": base64.b64encode(blob).decode()})
    r = answer(call(client, "files", {"action": "read", "path": "b.bin", "encoding": "base64"}))
    assert base64.b64decode(r["content"]) == blob
    assert "base64" in refusal(call(client, "files", {"action": "read", "path": "b.bin"}))
    call(client, "files", {"action": "write", "path": "t.txt", "content": "a"})
    call(client, "files", {"action": "write", "path": "t.txt", "content": "b", "append": True})
    assert answer(call(client, "files", {"action": "read", "path": "t.txt"}))["content"] == "ab"
    entries = answer(call(client, "files", {"action": "list"}))["entries"]
    assert {e["name"]: (e["type"], e["size"]) for e in entries} == {
        "b.bin": ("file", 256), "t.txt": ("file", 2)}


@pytest.mark.parametrize("path", ["../outside.txt", "a/../../outside.txt",
                                  "/etc/passwd", "/tmp/outside.txt", "..", "/"])
def test_files_refuse_to_leave_the_workspace(client, path):
    for args in ({"action": "read", "path": path},
                 {"action": "write", "path": path, "content": "x"},
                 {"action": "list", "path": path},
                 {"action": "run", "path": path}):
        assert "outside the workspace" in refusal(call(client, "files", args))


def test_files_refuse_a_symlink_out_of_the_workspace(client, workspace, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    (workspace / "link").symlink_to(secret)
    (workspace / "dirlink").symlink_to(tmp_path)
    assert "outside the workspace" in refusal(call(client, "files", {"action": "read", "path": "link"}))
    assert "outside the workspace" in refusal(call(
        client, "files", {"action": "write", "path": "dirlink/new.txt", "content": "x"}))
    assert not (tmp_path / "new.txt").exists()


def test_files_run_a_script_with_args(client, workspace):
    (workspace / "hi.py").write_text("import sys\nprint('hi', *sys.argv[1:])\n")
    r = answer(call(client, "files", {"action": "run", "path": "hi.py", "args": ["a", "b"]}))
    assert r["stdout"] == "hi a b\n" and r["exit_code"] == 0
    (workspace / "tool").write_text("#!/bin/sh\necho plain\n")
    assert "not executable" in refusal(call(client, "files", {"action": "run", "path": "tool"}))
    (workspace / "tool").chmod(0o755)
    assert answer(call(client, "files", {"action": "run", "path": "tool"}))["stdout"] == "plain\n"


def test_files_unknown_action(client):
    assert refusal(call(client, "files", {"action": "delete", "path": "x"})).startswith(
        "files: unknown action delete")


# -- capture ------------------------------------------------------------------

def paint_window(display_name, x, y, w, h, rgb, title=None):
    from Xlib import X, display as xdisplay

    d = xdisplay.Display(display_name)
    screen = d.screen()
    pixel = screen.default_colormap.alloc_color(*(c * 257 for c in rgb)).pixel
    window = screen.root.create_window(x, y, w, h, 0, screen.root_depth, X.InputOutput,
                                       X.CopyFromParent, background_pixel=pixel,
                                       override_redirect=True)
    if title:
        window.set_wm_name(title)
    window.map()
    d.sync()
    return d


def image_of(result):
    from PIL import Image

    assert result["isError"] is False, result
    block = result["content"][0]
    assert block["type"] == "image" and block["mimeType"] == "image/png"
    return Image.open(io.BytesIO(base64.b64decode(block["data"])))


@needs_xvfb
def test_capture_image_is_a_decodable_png_block(display, workspace):
    painter = paint_window(display, 0, 0, 800, 600, (255, 0, 0))
    client = TestClient(create_app(TOKEN, desktop=Desktop(display), workspace=str(workspace)))
    for mode in ("image", "png"):
        image = image_of(call(client, "capture", {"mode": mode})).convert("RGB")
        assert image.size == (800, 600)
        r, g, b = image.getpixel((400, 300))
        assert r > 200 and g < 60 and b < 60
    painter.close()


@needs_xvfb
def test_capture_image_scales_and_png_does_not(big_display, workspace):
    client = TestClient(create_app(TOKEN, desktop=Desktop(big_display), workspace=str(workspace)))
    scaled = call(client, "capture", {"mode": "image"})
    assert image_of(scaled).size == (1568, 784)
    assert "scaled from 2400x1200" in scaled["content"][1]["text"]
    assert image_of(call(client, "capture", {"mode": "png"})).size == (2400, 1200)


@needs_xvfb
def test_capture_region_and_window(display, workspace):
    back = paint_window(display, 0, 0, 800, 600, (0, 0, 255))
    front = paint_window(display, 100, 80, 200, 150, (0, 255, 0), title="Probe Window")
    client = TestClient(create_app(TOKEN, desktop=Desktop(display), workspace=str(workspace)))

    assert image_of(call(client, "capture", {"mode": "png", "region": [0, 0, 100, 50]})).size == (100, 50)
    # clipped at the screen edge
    assert image_of(call(client, "capture", {"mode": "png", "region": [700, 500, 500, 500]})).size == (100, 100)

    window = image_of(call(client, "capture", {"mode": "png", "window": "probe"})).convert("RGB")
    assert window.size == (200, 150)
    assert window.getpixel((100, 75))[1] > 200
    inside = image_of(call(client, "capture", {
        "mode": "png", "window": "probe window", "region": [10, 10, 50, 40]}))
    assert inside.size == (50, 40)

    problem = refusal(call(client, "capture", {"mode": "png", "window": "nothing"}))
    assert "no window is" in problem and "Probe Window" in problem
    assert "outside the screen" in refusal(call(
        client, "capture", {"mode": "png", "region": [5000, 5000, 10, 10]}))
    for d in (back, front):
        d.close()


@pytest.mark.parametrize("args,needle", [
    ({"mode": "gif"}, 'unknown action "gif"'),
    ({}, "unknown action"),
    ({"mode": "png", "region": [1, 2, 3]}, "region must be"),
    ({"mode": "png", "region": [0, 0, 0, 5]}, "region must be"),
    ({"mode": "png", "window": 3}, "window must be a string"),
    ({"mode": "tree", "region": [0, 0, 5, 5]}, "image and png only"),
])
def test_capture_argument_errors(client, args, needle):
    assert needle in refusal(call(client, "capture", args))


# -- browser without Chromium ---------------------------------------------------

def test_browser_says_so_when_chromium_is_unreachable(client):
    for args in ({"action": "title"}, {"action": "navigate", "url": "about:blank"}):
        assert "cannot reach Chromium" in refusal(call(client, "browser", args))
    assert "cannot reach Chromium" in refusal(call(client, "capture", {"mode": "tree"}))


@pytest.mark.parametrize("args,needle", [
    ({"action": "navigate", "url": "javascript:alert(1)"}, "url must be"),
    ({"action": "navigate"}, "url must be"),
    ({"action": "fill", "selector": "#a"}, "value must be a string"),
    ({"action": "click", "selector": ""}, "selector must be"),
    ({"action": "evaluate"}, "unknown action evaluate"),
])
def test_browser_argument_errors(client, args, needle):
    assert needle in refusal(call(client, "browser", args))


def test_render_tree_is_indented_text():
    nodes = [
        {"nodeId": "1", "role": {"value": "RootWebArea"}, "name": {"value": "T"},
         "childIds": ["2", "5"]},
        {"nodeId": "2", "role": {"value": "heading"}, "name": {"value": "Hello"},
         "childIds": ["3"]},
        {"nodeId": "3", "role": {"value": "StaticText"}, "name": {"value": "Hello"}},
        {"nodeId": "5", "role": {"value": "textbox"}, "name": {"value": "Email"},
         "value": {"value": "a@b.c"}},
    ]
    assert render_tree("T", "file:///x", nodes).splitlines() == [
        "# T - file:///x", 'RootWebArea "T"', '  heading "Hello"',
        '  textbox "Email" value="a@b.c"']
