"""Built-image smoke test. Set LOOM_TEST_IMAGE=<tag> to run it (needs docker):

    docker build -t loom-computer:test . && LOOM_TEST_IMAGE=loom-computer:test pytest tests/test_image.py
"""

import asyncio
import io
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest

IMAGE = os.environ.get("LOOM_TEST_IMAGE")
pytestmark = pytest.mark.skipif(not IMAGE, reason="LOOM_TEST_IMAGE not set")
TOKEN = "image-smoke-token"


def docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


@pytest.fixture(scope="module")
def container():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    name = f"loom-computer-test-{os.getpid()}"
    docker("run", "-d", "--name", name, "--cap-drop=ALL",
           "--security-opt", "no-new-privileges", "--shm-size=256m",
           "--pids-limit=512", "-m", "2g", "-p", f"127.0.0.1:{port}:8787",
           "-e", f"LOOM_COMPUTER_TOKEN={TOKEN}", IMAGE)
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        else:
            pytest.fail("container never became healthy:\n" + docker("logs", name).stdout)
        yield name, port
    finally:
        docker("rm", "-f", name, check=False)


def test_nothing_runs_as_root(container):
    name, _ = container
    users = docker("exec", name, "ps", "-eo", "user=").stdout.split()
    assert users and set(users) == {"agent"}


def test_desktop_processes_are_up_without_the_token(container):
    name, _ = container
    for proc in ("Xvfb", "openbox", "chromium"):
        deadline = time.time() + 30
        while docker("exec", name, "pgrep", "-x", proc, check=False).returncode:
            assert time.time() < deadline, f"{proc} is not running"
            time.sleep(0.5)
    leaked = docker("exec", name, "sh", "-c",
                    "for p in $(pgrep -x Xvfb; pgrep -x openbox; pgrep -x chromium); do "
                    "tr '\\0' '\\n' < /proc/$p/environ; done | grep -c LOOM_COMPUTER_TOKEN",
                    check=False).stdout.strip()
    assert leaked == "0"


def test_token_is_unreadable_to_other_processes(container):
    """From a plain `agent` process (as a workspace job or Chromium would be),
    no /proc/<pid>/environ holds the token, including the API's and PID 1's."""
    name, _ = container
    # `env -u` so this probe's own environment does not carry the token; docker exec inherits the container env so the strip must be outermost.
    probe = ("env -u LOOM_COMPUTER_TOKEN sh -c '"
             "readable=0; found=0; "
             "for f in /proc/[0-9]*/environ; do "
             "if tr \"\\0\" \"\\n\" < $f 2>/dev/null | grep -q " + TOKEN + "; then found=$((found+1)); fi; "
             "if cat $f >/dev/null 2>&1; then readable=$((readable+1)); fi; done; "
             "echo $found $readable'")
    found, readable = docker("exec", name, "env", "-u", "LOOM_COMPUTER_TOKEN", "sh", "-c", probe).stdout.split()
    assert found == "0"
    assert int(readable) > 0  # the probe really could read other processes
    # The two token holders specifically: PID 1 (init) and the API it forks.
    api = docker("exec", name, "pgrep", "-f", "loom_computer.init").stdout.split()
    assert "1" in api and len(api) >= 2
    for pid in api:
        r = docker("exec", name, "cat", f"/proc/{pid}/environ", check=False)
        assert r.returncode != 0 and TOKEN not in r.stdout


def test_screenshot_equivalent_over_ws(container):
    import websockets
    from PIL import Image

    _, port = container

    async def first_frame():
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={TOKEN}") as ws:
            hello = await ws.recv()
            return hello, await ws.recv()

    hello, frame = asyncio.run(first_frame())
    assert '"width": 1280' in hello and '"height": 800' in hello
    image = Image.open(io.BytesIO(frame))
    assert image.size == (1280, 800)
    assert len(set(image.convert("L").resize((64, 40)).getdata())) > 3  # not a blank screen


def test_missing_token_refuses_to_start():
    r = docker("run", "--rm", IMAGE, check=False)
    assert r.returncode != 0 and "LOOM_COMPUTER_TOKEN" in r.stderr


# -- Phase 2: the tools, against the real desktop --------------------------------

def mcp(port, name, arguments=None, token=TOKEN):
    import json

    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments or {}}}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp", data=body, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())["result"]


def tool(port, name, arguments=None):
    """A tool's JSON answer (the first text block), failing on isError."""
    import json

    result = mcp(port, name, arguments)
    assert result["isError"] is False, result
    return json.loads(result["content"][0]["text"])


PAGE = """<!doctype html><title>Loom Test Page</title>
<h1>Welcome</h1>
<input id="who" name="who" aria-label="Who">
<button id="go" onclick="document.title = 'Hello ' + document.getElementById('who').value;
  document.getElementById('out').textContent = 'clicked by ' + document.getElementById('who').value">Go</button>
<p id="out">not clicked</p>"""


def test_unauthenticated_tool_call_is_401(container):
    _, port = container
    with pytest.raises(urllib.error.HTTPError) as refused:
        mcp(port, "shell", {"command": "echo hi"}, token="wrong")
    assert refused.value.code == 401


def test_shell_runs_as_agent_without_the_token(container):
    _, port = container
    assert tool(port, "shell", {"command": "echo hello"})["stdout"] == "hello\n"
    assert tool(port, "shell", {"command": "id -un; pwd"})["stdout"] == \
        "agent\n/home/agent/workspace\n"
    env = tool(port, "shell", {"command": "env"})["stdout"]
    assert "LOOM_COMPUTER_TOKEN" not in env and TOKEN not in env
    environ = tool(port, "shell", {"command": "cat /proc/1/environ | wc -c"})
    assert environ["stdout"].strip() == "0"  # PID 1 holds the token and is unreadable


def test_files_round_trip_and_escape_refusal_in_the_image(container):
    _, port = container
    tool(port, "files", {"action": "write", "path": "t/in-image.txt", "content": "x"})
    assert tool(port, "files", {"action": "read", "path": "t/in-image.txt"})["content"] == "x"
    refused = mcp(port, "files", {"action": "read", "path": "../../../etc/passwd"})
    assert refused["isError"] is True and "outside the workspace" in refused["content"][0]["text"]


def wait_for_browser(port):
    deadline = time.time() + 60
    while True:
        result = mcp(port, "browser", {"action": "title"})
        if not result["isError"]:
            return
        assert time.time() < deadline, result
        time.sleep(0.5)


def test_browser_navigates_fills_and_clicks_a_local_page(container):
    _, port = container
    tool(port, "files", {"action": "write", "path": "page.html", "content": PAGE})
    wait_for_browser(port)

    page = tool(port, "browser", {"action": "navigate",
                                  "url": "file:///home/agent/workspace/page.html"})
    assert page["title"] == "Loom Test Page" and page["loaded"] is True
    assert tool(port, "browser", {"action": "title"})["title"] == "Loom Test Page"
    assert "Welcome" in tool(port, "browser", {"action": "text"})["text"]

    tool(port, "browser", {"action": "fill", "selector": "#who", "value": "Ada Lovelace"})
    tool(port, "browser", {"action": "click", "selector": "#go"})
    assert tool(port, "browser", {"action": "title"})["title"] == "Hello Ada Lovelace"
    assert tool(port, "browser", {"action": "text", "selector": "#out"})["text"] == \
        "clicked by Ada Lovelace"
    missing = mcp(port, "browser", {"action": "click", "selector": "#nope"})
    assert missing["isError"] is True and "no element" in missing["content"][0]["text"]


def test_capture_modes_against_the_real_desktop(container):
    import base64
    import json

    from PIL import Image

    _, port = container
    tool(port, "files", {"action": "write", "path": "page.html", "content": PAGE})
    wait_for_browser(port)
    tool(port, "browser", {"action": "navigate",
                           "url": "file:///home/agent/workspace/page.html"})

    def picture(arguments):
        result = mcp(port, "capture", arguments)
        assert result["isError"] is False, result
        block = result["content"][0]
        assert block["type"] == "image" and block["mimeType"] == "image/png"
        return Image.open(io.BytesIO(base64.b64decode(block["data"])))

    shot = picture({"mode": "image"})
    assert max(shot.size) <= 1568 and shot.size == (1280, 800)
    assert len(set(shot.convert("L").resize((64, 40)).getdata())) > 3
    assert picture({"mode": "png"}).size == (1280, 800)
    assert picture({"mode": "image", "region": [0, 0, 300, 200]}).size == (300, 200)
    window = picture({"mode": "png", "window": "chromium"})
    assert window.size[0] > 400 and window.size[1] > 300

    tree = mcp(port, "capture", {"mode": "tree"})
    assert tree["isError"] is False
    text = tree["content"][0]["text"]
    assert "Loom Test Page" in text and 'heading "Welcome"' in text and "textbox" in text
    state = mcp(port, "state", {"action": "guide"})
    assert json.loads(state["content"][0]["text"])["skill"].count("capture") > 3


def test_a_timed_out_job_is_killed_in_the_image(container):
    name, port = container
    result = tool(port, "shell", {"command": "sleep 300", "timeout": 1})
    assert result["timed_out"] is True
    assert docker("exec", name, "pgrep", "-x", "sleep", check=False).returncode != 0


# -- Phase 3: secrets against the real container and Chromium -------------------

P3_VALUE = "smoke-VARIABLE-7f3a9c"
P3_PASSWORD = "smoke-PASSWORD-1b2d4e"
P3_KEY = ("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRqWJh2dhYVVfPNQKF3jnILydYJT4"
          "fTQhJFl8xUdt4OihRANCAAQ0s8ww5WFY0AgGCAdAkSDRbOrTchhs35kPKnw4Yu9pEkWgx1NxdJvhF6qP"
          "oxMik67ig/aiCAiCSrQhog4v9wH0")
P3_CRED = "Y3JlZGVudGlhbC1pZC0wMTIzNDU2Nzg5"

P3_LOGIN_PAGE = """<!doctype html><title>login</title>
<input id="pw" type="password">
<p id="out">empty</p>
<script>document.getElementById('pw').addEventListener('input', e =>
  document.getElementById('out').textContent = 'len=' + e.target.value.length +
  ' value=' + e.target.value)</script>"""

P3_PASSKEY_PAGE = """<!doctype html><title>passkey</title><p id="out">pending</p>
<script>
const b = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
navigator.credentials.get({publicKey: {challenge: new Uint8Array(32), rpId: 'localhost',
  allowCredentials: [{type: 'public-key', id: b('%s')}], userVerification: 'preferred',
  timeout: 20000}})
  .then(c => document.getElementById('out').textContent = 'got ' + c.type + ' ' + c.id.length,
        e => document.getElementById('out').textContent = 'error ' + e.name);
</script>""" % P3_CRED

P3_CREATE_PAGE = """<!doctype html><title>create</title><p id="out">creating</p>
<script>
const out = t => document.getElementById('out').textContent = t;
navigator.credentials.create({publicKey: {challenge: new Uint8Array(32),
  rp: {id: 'localhost', name: 'Smoke Site'},
  user: {id: new Uint8Array([1, 2, 3]), name: 'alice', displayName: 'Alice'},
  pubKeyCredParams: [{type: 'public-key', alg: -7}],
  authenticatorSelection: {residentKey: 'required', userVerification: 'preferred'}}})
  .then(c => navigator.credentials.get({publicKey: {challenge: new Uint8Array(32),
          rpId: 'localhost', allowCredentials: [{type: 'public-key', id: c.rawId}],
          userVerification: 'preferred', timeout: 20000}})
        .then(a => out('created and got ' + a.type), e => out('created, get ' + e.name)),
        e => out('create ' + e.name));
</script>"""

# a page that navigates itself to the passkey page: its get() runs at load, with
# no look from the tools in between
P3_HOP_PAGE = """<!doctype html><title>hop</title><p id="out">pending</p>
<script>setTimeout(() => location.href = '/passkey.html?hop', 300)</script>"""


def http_json(port, method, path, body=None):
    import json

    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data, method=method,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null")


def page_text(port, selector="#out", until=lambda t: True, seconds=30):
    deadline = time.time() + seconds
    while True:
        text = tool(port, "browser", {"action": "text", "selector": selector})["text"]
        if until(text) or time.time() > deadline:
            return text
        time.sleep(0.3)


def test_phase3_secrets_in_the_real_container(container):
    import json

    name, port = container
    status, body = http_json(port, "PUT", "/secrets", {
        "SMOKE_VAR": P3_VALUE,
        "site": {"kind": "login", "sites": ["localhost"], "username": "alice",
                 "password": P3_PASSWORD},
        "pk": {"kind": "passkey", "rpId": "localhost", "credentialId": P3_CRED,
               "privateKey": P3_KEY, "userHandle": "AQID"}})
    assert status == 200 and body["variables"] == 1 and body["logins"] == 1
    assert http_json(port, "GET", "/secrets")[0] in (404, 405)

    # variable: present in the job, redacted from what comes back
    result = mcp(port, "shell", {"command": 'test "$SMOKE_VAR" = ' + P3_VALUE +
                                 ' && echo present; env | grep SMOKE_VAR'})
    text = json.dumps(result)
    assert "present" in text and "SMOKE_VAR=[REDACTED]" in text and P3_VALUE not in text
    assert "LOOM_COMPUTER_TOKEN" not in tool(port, "shell", {"command": "env"})["stdout"]
    # and not on disk
    on_disk = docker("exec", name, "sh", "-c",
                     f"grep -rl {P3_VALUE} /home/agent /tmp 2>/dev/null | wc -l").stdout.strip()
    assert on_disk == "0"

    for path, content in (("login.html", P3_LOGIN_PAGE), ("passkey.html", P3_PASSKEY_PAGE),
                          ("create.html", P3_CREATE_PAGE), ("hop.html", P3_HOP_PAGE)):
        tool(port, "files", {"action": "write", "path": f"site/{path}", "content": content})
    tool(port, "shell", {"command": "setsid -f python3 -m http.server 8099 --bind 127.0.0.1 "
                         "--directory /home/agent/workspace/site >/dev/null 2>&1 </dev/null"})
    time.sleep(1)
    wait_for_browser(port)

    # login: typed on its own site, refused on another
    tool(port, "browser", {"action": "navigate", "url": "http://localhost:8099/login.html"})
    tool(port, "browser", {"action": "fill", "selector": "#pw", "secret": "site"})
    typed = tool(port, "browser", {"action": "text", "selector": "#out"})["text"]
    assert typed == f"len={len(P3_PASSWORD)} value=[REDACTED]"
    tool(port, "browser", {"action": "navigate", "url": "http://127.0.0.1:8099/login.html"})
    refused = mcp(port, "browser", {"action": "fill", "selector": "#pw", "secret": "site"})
    assert refused["isError"] is True and "nothing was typed" in refused["content"][0]["text"]
    assert P3_PASSWORD not in json.dumps(refused)
    assert tool(port, "browser", {"action": "text", "selector": "#out"})["text"] == "empty"

    # passkey: the site's get() is answered by the virtual authenticator
    tool(port, "browser", {"action": "navigate", "url": "http://localhost:8099/passkey.html"})
    assert page_text(port, until=lambda t: t != "pending").startswith("got public-key")

    # a navigation the page makes itself: get() at load finds the authenticator
    tool(port, "browser", {"action": "navigate", "url": "http://localhost:8099/hop.html"})
    time.sleep(1.5)
    assert page_text(port, until=lambda t: t != "pending").startswith("got public-key")

    # nothing mints a passkey: create() is refused, and no get() can follow it
    tool(port, "browser", {"action": "navigate", "url": "http://localhost:8099/create.html"})
    assert page_text(port, until=lambda t: t != "creating") == "create NotAllowedError"

    # the whole container logged none of it
    logs = docker("logs", name)
    for secret in (P3_VALUE, P3_PASSWORD, P3_KEY):
        assert secret not in logs.stdout + logs.stderr
