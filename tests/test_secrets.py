"""Phase 3: secrets, logins, redaction.

Browser behavior runs against a fake DevTools endpoint that answers the few
calls the computer makes and records the rest; the real Chromium is covered
by the image smoke test (tests/test_image.py and the Phase 3 smoke notes).
"""

import asyncio
import base64
import json
import logging
import re
import threading
import time
from http import HTTPStatus

import pytest
from fastapi.testclient import TestClient
from websockets.asyncio.server import serve
from websockets.datastructures import Headers
from websockets.http11 import Response

from loom_computer.app import create_app
from loom_computer.browser import Browser
from loom_computer.secrets import SecretStore, SecretsError, site_allows, totp_code

from test_tools import AUTH, answer, call, refusal

TOKEN = "tools-token"
VAR_VALUE = "hunter2-VARIABLE-value"
PASSWORD = "p4ss-w0rd-NEVER-LEAK"
USERNAME = "alice@example.com"
KEY = ("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRqWJh2dhYVVfPNQKF3jnILydYJT4"
       "fTQhJFl8xUdt4OihRANCAAQ0s8ww5WFY0AgGCAdAkSDRbOrTchhs35kPKnw4Yu9pEkWgx1NxdJvhF6qP"
       "oxMik67ig/aiCAiCSrQhog4v9wH0")
CRED_ID = base64.b64encode(b"credential-id-0123456789").decode()
HANDLE = base64.b64encode(b"user-handle").decode()
LOGIN = {"kind": "login", "sites": ["example.com"], "username": USERNAME,
         "password": PASSWORD}
PASSKEY = {"kind": "passkey", "rpId": "example.com", "credentialId": CRED_ID,
           "privateKey": KEY, "userHandle": HANDLE, "userName": "alice"}


class FakeCDP:
    """Tabs on one port: /json/list over HTTP, and a CDP socket per tab."""

    def __init__(self, origins):
        self.origins = list(origins)  # one page origin per tab
        self.fills: list[str] = []  # expressions that typed something
        self.calls: list[tuple[int, str, dict]] = []
        self.sockets: dict[int, object] = {}
        self.page_text = ""  # what `browser text` finds on every page
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> str:
        self._thread.start()
        assert self._ready.wait(5)
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.loop.call_soon_threadsafe(self.stop_event.set)

    def _run(self):
        async def main():
            self.loop = asyncio.get_running_loop()
            self.stop_event = asyncio.Event()
            async with serve(self._handle, "127.0.0.1", 0,
                             process_request=self._http) as server:
                self.port = server.sockets[0].getsockname()[1]
                self._ready.set()
                await self.stop_event.wait()
        asyncio.run(main())

    def _http(self, connection, request):
        if request.path == "/json/list":
            body = json.dumps([
                {"id": f"tab{i}", "type": "page", "url": origin + "/",
                 "webSocketDebuggerUrl": f"ws://127.0.0.1:{self.port}/{i}"}
                for i, origin in enumerate(self.origins)]).encode()
            return Response(200, "OK", Headers(
                {"Content-Type": "application/json", "Content-Length": str(len(body))}), body)
        return None

    async def _handle(self, socket):
        index = int(socket.request.path.strip("/"))
        self.sockets[index] = socket
        async for raw in socket:
            msg = json.loads(raw)
            method, params = msg["method"], msg.get("params", {})
            self.calls.append((index, method, params))
            result = self._answer(index, method, params)
            await socket.send(json.dumps({"id": msg["id"], "result": result}))

    def _answer(self, index, method, params):
        if method == "Runtime.evaluate":
            expression = params.get("expression", "")
            origin = self.origins[index]
            if "visibilityState" in expression:
                value = ["visible", True]
            elif expression == "document.readyState":
                value = "complete"
            elif expression.strip() in ("() => location.origin", "(() => location.origin)()",
                                        "location.origin"):
                value = origin
            elif "location.origin !== origin" in expression:
                # the atomic fill: typed only if the page is still the checked origin
                checked = json.loads(expression.rsplit(", ", 1)[1].rstrip(")"))
                if checked != origin:
                    value = {"error": "the page changed; nothing was typed"}
                else:
                    self.fills.append(expression)
                    value = {"filled": "input"}
            elif "el.innerText" in expression:
                value = {"text": self.page_text}
            else:
                value = None
            return {"result": {"value": value}}
        return {}

    # -- driving the page side --------------------------------------------------

    def event(self, index, method, params):
        future = asyncio.run_coroutine_threadsafe(
            self.sockets[index].send(json.dumps({"method": method, "params": params})),
            self.loop)
        future.result(5)


def wait_for(condition, seconds=5.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    return root


@pytest.fixture
def make(workspace):
    started = []

    def build(origins=("https://example.com",)):
        fake = FakeCDP(origins)
        started.append(fake)
        endpoint = fake.start()
        browser = Browser(endpoint)
        app = create_app(TOKEN, workspace=str(workspace), browser=browser)
        return fake, TestClient(app)
    yield build
    for fake in started:
        fake.stop()


@pytest.fixture
def client(workspace):
    with TestClient(create_app(TOKEN, workspace=str(workspace),
                               browser=Browser("http://127.0.0.1:1"))) as c:
        yield c


def put_secrets(client, body, headers=AUTH):
    return client.put("/secrets", content=json.dumps(body), headers=headers)


# -- PUT /secrets ---------------------------------------------------------------

def test_put_secrets_needs_bearer(client):
    assert client.put("/secrets", json={}).status_code == 401
    assert client.put("/secrets", json={},
                      headers={"Authorization": "Bearer nope"}).status_code == 401


def test_there_is_no_get_for_secrets(client):
    put_secrets(client, {"V": VAR_VALUE})
    for path in ("/secrets", "/secrets/V"):
        r = client.get(path, headers=AUTH)
        assert r.status_code in (404, 405)
        assert VAR_VALUE not in r.text


def test_put_answers_counts_not_values(client):
    r = put_secrets(client, {"V": VAR_VALUE, "L": LOGIN})
    assert r.status_code == 200
    assert r.json() == {"ok": True, "variables": 1, "logins": 1}
    for value in (VAR_VALUE, PASSWORD, USERNAME, KEY):
        assert value not in r.text


@pytest.mark.parametrize("body", [
    [], "x", {"A": 5}, {"A": {"kind": "weird"}}, {"A": {"kind": "login"}},
    {"A": {"kind": "login", "sites": [], "username": "u", "password": "p"}},
    {"A": {"kind": "login", "sites": ["a.com"], "username": "u"}},
    {"A": {"kind": "login", "sites": ["a.com"], "username": "u", "password": "p",
           "totp": "!!notbase32!!"}},
])
def test_invalid_sets_are_400_and_change_nothing(client, body):
    put_secrets(client, {"KEEP": VAR_VALUE})
    r = put_secrets(client, body)
    assert r.status_code == 400
    out = answer(call(client, "shell", {"command": "echo -n $KEEP | wc -c"}))
    assert out["stdout"].strip() == str(len(VAR_VALUE))  # the old set stands


def test_a_passkey_refuses_the_whole_set_naming_the_secret_only(client):
    put_secrets(client, {"KEEP": VAR_VALUE})
    r = put_secrets(client, {"V": "other-value-1", "my_key": PASSKEY})
    assert r.status_code == 400
    assert "my_key" in r.json()["error"]
    for value in (KEY, CRED_ID, HANDLE, "other-value-1"):
        assert value not in r.text
    out = answer(call(client, "shell", {"command": "echo -n $KEEP; echo -n $V"}))
    assert out["stdout"] == "[REDACTED]"  # the old set stands, nothing half-applied
    assert put_secrets(client, {"V": VAR_VALUE}).status_code == 200  # a clean set still works


def test_invalid_json_and_validation_never_echo_the_input(client):
    r = client.put("/secrets", content='{"V": "sekrit-in-bad-json', headers=AUTH)
    assert r.status_code == 400 and "sekrit" not in r.text
    r = put_secrets(client, {"A": {"kind": "login", "sites": ["a.com"],
                                   "username": "sekrit-user", "password": 7}})
    assert r.status_code == 400 and "sekrit" not in r.text


def test_put_replaces_the_whole_set(client):
    put_secrets(client, {"ONE": "first-value-1"})
    put_secrets(client, {"TWO": "second-value-2"})
    out = answer(call(client, "shell", {"command": "env | grep -c '^ONE='; echo ${TWO:+set}"}))
    assert out["stdout"].split() == ["0", "set"]


# -- variables ------------------------------------------------------------------

def test_variable_is_in_the_job_env_and_redacted_from_output(client):
    put_secrets(client, {"MY_TOKEN": VAR_VALUE})
    present = answer(call(client, "shell", {
        "command": 'test "$MY_TOKEN" = "' + VAR_VALUE + '" && echo present'}))
    assert present["stdout"] == "present\n"
    echoed = answer(call(client, "shell", {"command": "echo value=$MY_TOKEN; env"}))
    assert VAR_VALUE not in json.dumps(echoed)
    assert "value=[REDACTED]" in echoed["stdout"] and "MY_TOKEN=[REDACTED]" in echoed["stdout"]
    raw = call(client, "shell", {"command": "echo $MY_TOKEN"})
    assert VAR_VALUE not in json.dumps(raw)  # text block and structuredContent both


def test_variable_reaches_files_run_and_argv(client, workspace):
    put_secrets(client, {"MY_TOKEN": VAR_VALUE})
    (workspace / "s.sh").write_text('[ "$MY_TOKEN" = "' + VAR_VALUE + '" ] && echo ok\n')
    assert answer(call(client, "files", {"action": "run", "path": "s.sh"}))["stdout"] == "ok\n"
    out = answer(call(client, "shell", {"argv": ["printenv", "MY_TOKEN"]}))
    assert out["stdout"] == "[REDACTED]\n" and out["exit_code"] == 0


def test_jobs_do_not_inherit_the_bearer(client, monkeypatch):
    monkeypatch.setenv("LOOM_COMPUTER_TOKEN", TOKEN)
    put_secrets(client, {"MY_TOKEN": VAR_VALUE, "LOOM_COMPUTER_TOKEN": "forged-bearer"})
    out = answer(call(client, "shell", {"command": "env"}))
    assert "LOOM_COMPUTER_TOKEN" not in out["stdout"]
    assert TOKEN not in out["stdout"] and "forged-bearer" not in out["stdout"]


def test_variables_are_not_written_into_the_workspace(client, workspace):
    """The workspace's .loom/env is where a preparation job's captured
    environment lands; granted variables never go there."""
    (workspace / ".loom").mkdir()
    (workspace / ".loom" / "env").write_text("FROM_PREP=prepared\n")
    put_secrets(client, {"MY_TOKEN": VAR_VALUE})
    answer(call(client, "shell", {"command": "true"}))
    assert (workspace / ".loom" / "env").read_text() == "FROM_PREP=prepared\n"
    for path in workspace.rglob("*"):
        if path.is_file():
            assert VAR_VALUE.encode() not in path.read_bytes()


def test_a_prep_job_environment_has_no_variables(workspace):
    """What the desk's preparation job sees is the plain job environment
    (`base_env` + workspace env): the computer merges variables only in
    Tools._job_env, the path of shell and files run."""
    from types import SimpleNamespace
    from loom_computer.jobs import base_env, workspace_env
    from loom_computer.tools import Tools

    tools = Tools(lambda: {}, SimpleNamespace(display=":0"), str(workspace))
    tools.secrets.replace({"MY_TOKEN": VAR_VALUE})
    assert tools._job_env()["MY_TOKEN"] == VAR_VALUE
    prep = {**base_env(":0"), **workspace_env(str(workspace))}
    assert "MY_TOKEN" not in prep


def test_redaction_covers_files_read_and_errors(client, workspace):
    put_secrets(client, {"MY_TOKEN": VAR_VALUE, "L": LOGIN})
    (workspace / "n.txt").write_text(f"token {VAR_VALUE} and {PASSWORD} and {USERNAME}")
    got = answer(call(client, "files", {"action": "read", "path": "n.txt"}))
    assert got["content"] == "token [REDACTED] and [REDACTED] and [REDACTED]"
    bad = refusal(call(client, "files", {"action": "read", "path": VAR_VALUE}))
    assert VAR_VALUE not in bad


def test_base64_read_masks_raw_bytes_at_every_offset(client, workspace):
    import os
    put_secrets(client, {"MY_TOKEN": VAR_VALUE})
    value = VAR_VALUE.encode()
    filler = os.urandom(300).replace(value, b"")
    for offset in (0, 1, 2, 5, 150):
        (workspace / "b.bin").write_bytes(filler[:offset] + value + filler[offset:])
        got = answer(call(client, "files", {"action": "read", "path": "b.bin",
                                            "encoding": "base64"}))
        raw = base64.b64decode(got["content"])
        assert value not in raw and VAR_VALUE not in got["content"]
        assert raw == filler[:offset] + b"[REDACTED]" + filler[offset:]
        assert got["bytes"] == len(raw)


def test_base64_read_of_clean_binary_round_trips(client, workspace):
    import os
    put_secrets(client, {"MY_TOKEN": VAR_VALUE})
    data = os.urandom(512)
    (workspace / "c.bin").write_bytes(data)
    got = answer(call(client, "files", {"action": "read", "path": "c.bin",
                                        "encoding": "base64"}))
    assert base64.b64decode(got["content"]) == data and got["bytes"] == 512


def test_malformed_set_errors_name_the_secret(client):
    bad_site = {"kind": "login", "sites": ["not a host!"], "username": "u", "password": "p"}
    r = put_secrets(client, {"SITEY": bad_site})
    assert r.status_code == 400 and "SITEY" in r.text and "login site" in r.text
    r = put_secrets(client, {"KINDY": {"kind": "wat"}})
    assert r.status_code == 400 and "KINDY" in r.text and "kind" in r.text


def test_redaction_masks_json_escaped_forms(client):
    tricky = 'quo"te\\back'
    put_secrets(client, {"T": tricky})
    out = call(client, "shell", {"command": "printf %s \"$T\""})
    assert answer(out)["stdout"] == "[REDACTED]"
    # the text block is JSON, so it carries the escaped form: masked too
    assert "quo" not in out["content"][0]["text"] and "back" not in out["content"][0]["text"]


def test_redaction_masks_every_json_escape_form(client, workspace):
    # json.dumps writes these as \u00e9, \u2603, \b, \f, \u001f ... (a NUL is
    # refused in a variable at PUT, so it is not here)
    tricky = "pre\b\f\u001f\u00e9\u2603\U0001F600post"
    (workspace / "t.txt").write_text(tricky, encoding="utf-8")
    put_secrets(client, {"T": tricky, "U": "caf\u00e9-\u2603-\x01\x1b-end"})
    results = [
        call(client, "files", {"action": "read", "path": "t.txt"}),
        call(client, "shell", {"command": "printf %s \"$U\"; printf %s \"$U\" >&2"}),
        call(client, "files", {"action": "read", "path": "../" + "x" * 3 + tricky}),
        call(client, "shell", {"command": "echo hi", "cwd": tricky}),
    ]
    for result in results:
        blob = json.dumps(result) + result["content"][0]["text"]
        for piece in ("\\b", "\\f", "\\u001f", "\\u00e9", "\\u2603",
                      "\\u0001", "\\u001b", "post", "-end", "caf"):
            assert piece not in blob, (piece, blob)
        assert "pre" not in result["content"][0]["text"].replace("[REDACTED]", "")
    assert "[REDACTED]" in results[0]["content"][0]["text"]
    assert answer(results[1])["stdout"] == "[REDACTED]"


# -- revocation and short-lived values ---------------------------------------------

def test_a_replaced_value_stays_masked_for_the_job_that_holds_it(client, workspace):
    put_secrets(client, {"OLD": VAR_VALUE})
    out = {}

    def run():
        out["result"] = call(client, "shell", {
            "command": "touch started; while [ ! -e go ]; do sleep 0.05; done; "
                       "printf %s \"$OLD\"; printf %s \"$OLD\" >&2"})
    job = threading.Thread(target=run)
    job.start()
    assert wait_for(lambda: (workspace / "started").exists())
    put_secrets(client, {})  # the value is revoked while the job still holds it
    (workspace / "go").write_text("")
    job.join(10)
    result = answer(out["result"])
    assert result["stdout"] == "[REDACTED]" and result["stderr"] == "[REDACTED]"
    assert VAR_VALUE not in json.dumps(out["result"])
    # and once no job holds it, the mask is gone with the value
    assert answer(call(client, "shell", {"command": "echo " + VAR_VALUE}))["stdout"] \
        == VAR_VALUE + "\n"


def test_a_generated_totp_code_is_masked_on_the_page(make):
    fake, client = make(["https://example.com"])
    put_secrets(client, {"L": {**LOGIN, "totp": "JBSWY3DPEHPK3PXP"}})
    answer(call(client, "browser", {"action": "fill", "selector": "#c",
                                    "secret": "L", "field": "totp"}))
    code = json.loads(fake.fills[0].rsplit(", ", 2)[1])
    fake.page_text = f"We saw the code {code} in the field"
    shown = call(client, "browser", {"action": "text"})
    assert code not in json.dumps(shown)
    assert answer(shown)["text"] == "We saw the code [REDACTED] in the field"


def test_a_timed_mask_expires():
    store = SecretStore()
    store.remember_for("123456", 0.05)
    assert store.redact("code 123456") == "code [REDACTED]"
    time.sleep(0.1)
    assert store.redact("code 123456") == "code 123456"


# -- in memory only -------------------------------------------------------------

def test_restart_clears_the_set(workspace):
    first = TestClient(create_app(TOKEN, workspace=str(workspace),
                                  browser=Browser("http://127.0.0.1:1")))
    put_secrets(first, {"MY_TOKEN": VAR_VALUE})
    assert answer(call(first, "shell", {"command": "echo ${MY_TOKEN:+yes}"}))["stdout"] == "yes\n"
    second = TestClient(create_app(TOKEN, workspace=str(workspace),
                                   browser=Browser("http://127.0.0.1:1")))
    assert answer(call(second, "shell", {"command": "echo ${MY_TOKEN:+yes}"}))["stdout"] == "\n"


def test_nothing_is_written_to_disk(client, workspace, tmp_path, monkeypatch):
    opened = []
    real_open = open

    def spy(file, mode="r", *a, **k):
        if any(c in mode for c in "wax+") and not str(file).startswith("/dev/"):
            opened.append(str(file))
        return real_open(file, mode, *a, **k)
    monkeypatch.setattr("builtins.open", spy)
    put_secrets(client, {"V": VAR_VALUE, "L": LOGIN})
    assert opened == []


# -- no secret in logs or output ------------------------------------------------

def test_no_secret_value_appears_in_logs_or_tool_output(client, workspace, caplog, capfd):
    caplog.set_level(logging.DEBUG)
    body = {"V": VAR_VALUE, "L": {**LOGIN, "totp": "JBSWY3DPEHPK3PXP"}}
    seen = [put_secrets(client, body).text]
    secrets = [VAR_VALUE, PASSWORD, USERNAME, "JBSWY3DPEHPK3PXP"]
    (workspace / "leak.txt").write_text("\n".join(secrets))
    for name, args in (
            ("shell", {"command": "env; echo $V"}),
            ("shell", {"command": "cat leak.txt; echo " + " ".join(secrets) + " >&2; exit 1"}),
            ("files", {"action": "read", "path": "leak.txt"}),
            ("files", {"action": "list"}),
            ("browser", {"action": "fill", "selector": "#a", "secret": "L"}),
            ("browser", {"action": "text"}),
            ("state", {"action": "guide"}),
            ("state", {"action": "x " + PASSWORD}),
            ("capture", {"mode": "tree"}),
            ("shell", {"command": "x" * 3, "cwd": PASSWORD})):
        seen.append(json.dumps(call(client, name, args)))
    # A tool that blows up logs its traceback; that is masked as well.
    logging.getLogger("loom_computer").error("leaky %s", VAR_VALUE)
    try:
        raise RuntimeError(PASSWORD)
    except RuntimeError:
        logging.getLogger("loom_computer").exception("boom")
    out, err = capfd.readouterr()
    logs = caplog.text + "".join(r.getMessage() for r in caplog.records) + out + err
    blob = "\n".join(seen) + logs
    for value in secrets:
        assert value not in blob, f"{value!r} leaked"
    assert "[REDACTED]" in blob


def test_log_filter_masks_the_value_in_a_handler_stream():
    store = SecretStore()
    store.replace({"V": VAR_VALUE})
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "got %s", (VAR_VALUE,), None)
    assert store.log_filter().filter(record) is True
    assert VAR_VALUE not in record.getMessage()


# -- logins: site scoping ---------------------------------------------------------

@pytest.mark.parametrize("sites,origin,ok", [
    (["example.com"], "https://example.com", True),
    (["example.com"], "https://login.example.com", True),
    (["example.com"], "https://evilexample.com", False),
    (["example.com"], "https://example.com.evil.test", False),
    (["example.com"], "http://example.com", False),  # a bare host means https
    (["http://example.com"], "http://example.com", True),
    (["https://example.com:8443"], "https://example.com:8443", True),
    (["https://example.com:8443"], "https://example.com", False),
    (["example.com"], "null", False),
    (["example.com"], "file://", False),
    (["example.com"], "about:blank", False),
    (["localhost"], "http://localhost:8099", True),
    (["a.test", "b.test"], "https://b.test", True),
])
def test_site_allows(sites, origin, ok):
    assert site_allows(tuple(sites), origin) is ok


def test_fill_secret_on_the_logins_own_site(make):
    fake, client = make(["https://example.com"])
    put_secrets(client, {"L": LOGIN})
    r = answer(call(client, "browser", {"action": "fill", "selector": "#pw", "secret": "L"}))
    assert r["filled"] == "input" and r["field"] == "password"
    assert len(fake.fills) == 1 and json.dumps(PASSWORD) in fake.fills[0]
    answer(call(client, "browser", {"action": "fill", "selector": "#u",
                                    "secret": "L", "field": "username"}))
    assert json.dumps(USERNAME) in fake.fills[1]


def test_fill_secret_refused_on_another_site(make):
    fake, client = make(["https://evil.test"])
    put_secrets(client, {"L": LOGIN})
    r = call(client, "browser", {"action": "fill", "selector": "#pw", "secret": "L"})
    text = refusal(r)
    assert "nothing was typed" in text and PASSWORD not in text
    assert fake.fills == []


def test_fill_secret_totp_is_computed(make):
    fake, client = make(["https://example.com"])
    put_secrets(client, {"L": {**LOGIN, "totp": "JBSWY3DPEHPK3PXP"}})
    answer(call(client, "browser", {"action": "fill", "selector": "#c",
                                    "secret": "L", "field": "totp"}))
    code = json.loads(fake.fills[0].rsplit(", ", 2)[1])
    assert len(code) == 6 and code.isdigit()


def test_fill_secret_errors(make):
    _, client = make(["https://example.com"])
    put_secrets(client, {"L": LOGIN, "V": VAR_VALUE})
    assert "no granted login" in refusal(call(client, "browser", {
        "action": "fill", "selector": "#a", "secret": "V"}))  # a variable is not a login
    assert "not both" in refusal(call(client, "browser", {
        "action": "fill", "selector": "#a", "secret": "L", "value": "x"}))
    assert "totp" in refusal(call(client, "browser", {
        "action": "fill", "selector": "#a", "secret": "L", "field": "totp"}))


def test_totp_matches_rfc6238_vectors():
    key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"
    assert totp_code(key, 59, digits=8) == "94287082"
    assert totp_code(key, 1111111109, digits=8) == "07081804"


# -- store-level ------------------------------------------------------------------

def test_store_rejects_without_echo():
    store = SecretStore()
    with pytest.raises(SecretsError) as raised:
        store.replace({"X": {"kind": "login", "sites": ["a.com"],
                             "username": "u-secret", "password": ""}})
    assert "u-secret" not in str(raised.value)


# -- /files/download masks granted values -----------------------------------------

def test_download_masks_a_granted_value(client, workspace):
    put_secrets(client, {"V": VAR_VALUE})
    pad = b"." * (65536 - 7)  # the value straddles the first chunk boundary
    (workspace / "big.bin").write_bytes(pad + VAR_VALUE.encode() + b"\x00tail")
    r = client.get("/files/download", params={"path": "big.bin"}, headers=AUTH)
    assert r.status_code == 200
    assert VAR_VALUE.encode() not in r.content
    assert r.content == pad + b"[REDACTED]\x00tail"
    cut = client.get("/files/download", params={"path": "big.bin", "max_bytes": "5"},
                     headers=AUTH)
    assert cut.content == b"....."


def test_download_is_unchanged_without_a_matching_value(client, workspace):
    put_secrets(client, {"V": VAR_VALUE})
    (workspace / "plain.bin").write_bytes(b"\x00\x01 nothing here")
    r = client.get("/files/download", params={"path": "plain.bin"}, headers=AUTH)
    assert r.content == b"\x00\x01 nothing here"


# -- round 2: download masking is live, truncation counts masked bytes -------------

def test_download_masks_a_value_granted_mid_stream(workspace):
    app = create_app(TOKEN, workspace=str(workspace), browser=Browser("http://127.0.0.1:1"))
    later = "late-granted-value"
    pad = b"." * (65536 * 3)
    (workspace / "slow.bin").write_bytes(pad + later.encode() + b"-end")

    async def run():
        sent, granted, body = [], False, b""
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "method": "GET", "scheme": "http", "path": "/files/download",
                 "raw_path": b"/files/download", "root_path": "",
                 "query_string": b"path=slow.bin", "server": ("t", 80),
                 "client": ("c", 1),
                 "headers": [(b"authorization", f"Bearer {TOKEN}".encode())]}

        async def receive():
            await asyncio.sleep(3600)

        async def send(message):
            nonlocal granted, body
            if message["type"] == "http.response.body":
                body += message.get("body", b"")
                if not granted:  # the first bytes are out; now the value is granted
                    granted = True
                    app.state.secrets.replace({"L": later})
        await app(scope, receive, send)
        return body

    body = asyncio.run(run())
    assert later.encode() not in body
    assert body.endswith(b"[REDACTED]-end")


def test_download_truncation_counts_masked_bytes(client, workspace):
    put_secrets(client, {"V": "x"})  # one byte becomes ten
    (workspace / "m.bin").write_bytes(b"axb")
    r = client.get("/files/download", params={"path": "m.bin", "max_bytes": "4"},
                   headers=AUTH)
    assert r.status_code == 200
    assert r.content == b"a[RE"
    assert len(r.content) == 4
    assert r.headers["X-Loom-Truncated"] == "true"
    # 3 raw bytes but 3 masked bytes fit exactly under a larger cut: not truncated
    (workspace / "n.bin").write_bytes(b"abc")
    r = client.get("/files/download", params={"path": "n.bin", "max_bytes": "3"},
                   headers=AUTH)
    assert r.content == b"abc" and r.headers["X-Loom-Truncated"] == "false"
    # raw size 12 is over the cut, but the masked body is [REDACTED] (10 <= 10)
    (workspace / "o.bin").write_bytes(b"xxxxxxxxxx")
    r = client.get("/files/download", params={"path": "o.bin", "max_bytes": "100"},
                   headers=AUTH)
    assert r.content == b"[REDACTED]" * 10 and r.headers["X-Loom-Truncated"] == "false"


# -- round 2: JSON escape spellings in error text, NUL variables -------------------

def test_every_json_escape_spelling_of_a_value_is_masked():
    store = SecretStore()
    value = "café/\b\f\n\r\t\"\\\U0001f600\x1f-tail"
    store.replace({"V": value})
    spellings = {json.dumps(value, ensure_ascii=True)[1:-1],
                 json.dumps(value, ensure_ascii=False)[1:-1]}
    spellings |= {re.sub(r"\\u([0-9a-f]{4})", lambda m: "\\u" + m.group(1).upper(), s)
                  for s in list(spellings)}
    spellings |= {s.replace("/", "\\/") for s in list(spellings)}
    assert len(spellings) >= 4
    for spelling in spellings:
        assert store.redact(f"error: {spelling}!") == "error: [REDACTED]!"


def test_error_holding_the_json_escaped_value_is_masked(client):
    value = "café-s3cret"
    put_secrets(client, {"V": value})
    escaped = json.dumps(value)[1:-1]  # café-s3cret as an error might spell it
    assert "\\u00e9" in escaped
    for spelling in (escaped, escaped.replace("\\u00e9", "\\u00E9")):
        text = refusal(call(client, "files", {"action": "read", "path": spelling}))
        assert "s3cret" not in text and "caf" not in text


def test_nul_in_a_variable_is_refused_naming_the_secret_not_the_value(client):
    put_secrets(client, {"KEEP": VAR_VALUE})
    r = put_secrets(client, {"MY_NUL": "sekrit\x00tail"})
    assert r.status_code == 400
    assert "MY_NUL" in r.text and "sekrit" not in r.text and "tail" not in r.text
    out = answer(call(client, "shell", {"command": "echo -n $KEEP | wc -c"}))
    assert out["stdout"].strip() == str(len(VAR_VALUE))  # the old set stands
