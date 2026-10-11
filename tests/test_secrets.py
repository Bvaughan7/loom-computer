"""Phase 3: secrets, logins, passkeys, registration arming, redaction.

Browser behavior runs against a fake DevTools endpoint that answers the few
calls the computer makes and records the rest; the real Chromium is covered
by the image smoke test (tests/test_image.py and the Phase 3 smoke notes).
"""

import asyncio
import base64
import json
import logging
import os
import threading
import time
from http import HTTPStatus

import pytest
from fastapi.testclient import TestClient
from websockets.asyncio.server import serve
from websockets.datastructures import Headers
from websockets.http11 import Response

from loom_computer import passkeys as passkeys_module
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
        self.credentials: dict[int, dict[str, dict]] = {}
        self.sockets: dict[int, object] = {}
        self.bindings: dict[int, list] = {}
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
        self.credentials.setdefault(index, {})
        async for raw in socket:
            msg = json.loads(raw)
            method, params = msg["method"], msg.get("params", {})
            self.calls.append((index, method, params))
            result = self._answer(index, method, params)
            await socket.send(json.dumps({"id": msg["id"], "result": result}))

    def _answer(self, index, method, params):
        creds = self.credentials[index]
        if method == "WebAuthn.addVirtualAuthenticator":
            return {"authenticatorId": f"auth{index}"}
        if method == "WebAuthn.addCredential":
            creds[params["credential"]["credentialId"]] = params["credential"]
            return {}
        if method == "WebAuthn.getCredentials":
            return {"credentials": list(creds.values())}
        if method == "WebAuthn.removeCredential":
            creds.pop(params["credentialId"], None)
            return {}
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
            elif "__loomRelease" in expression:
                value = True
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

    def page_calls_create(self, index, **ask):
        self.event(index, "Runtime.bindingCalled", {
            "name": passkeys_module.BINDING, "executionContextId": 7,
            "payload": json.dumps({"id": os.urandom(16).hex(), **ask})})

    def release_modes(self):
        out = []
        for _, method, params in self.calls:
            if (method == "Runtime.evaluate" and "contextId" in params
                    and "__loomRelease" in params.get("expression", "")):
                out.append(json.loads(params["expression"].rsplit(", ", 1)[1].rstrip(")")))
        return out

    def mint(self, index, rp_id="example.com", ident=b"minted-credential", handle=HANDLE):
        credential = {"credentialId": base64.b64encode(ident).decode(), "rpId": rp_id,
                      "isResidentCredential": True, "privateKey": KEY,
                      "userHandle": handle, "signCount": 0}
        self.credentials[index][credential["credentialId"]] = credential
        self.event(index, "WebAuthn.credentialAdded",
                   {"authenticatorId": f"auth{index}", "credential": credential})
        return credential


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

    def build(origins=("https://example.com",), clock=None):
        fake = FakeCDP(origins)
        started.append(fake)
        endpoint = fake.start()
        browser = Browser(endpoint)
        app = create_app(TOKEN, workspace=str(workspace), browser=browser)
        if clock is not None:
            app.state.passkeys._clock = clock
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
    r = put_secrets(client, {"V": VAR_VALUE, "L": LOGIN, "P": PASSKEY})
    assert r.status_code == 200
    assert r.json() == {"ok": True, "variables": 1, "logins": 1, "passkeys": 1}
    for value in (VAR_VALUE, PASSWORD, USERNAME, KEY):
        assert value not in r.text


@pytest.mark.parametrize("body", [
    [], "x", {"A": 5}, {"A": {"kind": "weird"}}, {"A": {"kind": "login"}},
    {"A": {"kind": "login", "sites": [], "username": "u", "password": "p"}},
    {"A": {"kind": "login", "sites": ["a.com"], "username": "u"}},
    {"A": {"kind": "login", "sites": ["a.com"], "username": "u", "password": "p",
           "totp": "!!notbase32!!"}},
    {"A": {"kind": "passkey", "rpId": "a.com"}},
    {"A": {"kind": "passkey", "rpId": "a.com", "credentialId": "***", "privateKey": "x"}},
])
def test_invalid_sets_are_400_and_change_nothing(client, body):
    put_secrets(client, {"KEEP": VAR_VALUE})
    r = put_secrets(client, body)
    assert r.status_code == 400
    out = answer(call(client, "shell", {"command": "echo -n $KEEP | wc -c"}))
    assert out["stdout"].strip() == str(len(VAR_VALUE))  # the old set stands


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


def test_redaction_masks_json_escaped_forms(client):
    tricky = 'quo"te\\back'
    put_secrets(client, {"T": tricky})
    out = call(client, "shell", {"command": "printf %s \"$T\""})
    assert answer(out)["stdout"] == "[REDACTED]"
    # the text block is JSON, so it carries the escaped form: masked too
    assert "quo" not in out["content"][0]["text"] and "back" not in out["content"][0]["text"]


def test_redaction_masks_every_json_escape_form(client, workspace):
    # json.dumps writes these as \u00e9, \u2603, \u0000, \b, \f, \u001f ...
    tricky = "pre\u0000\b\f\u001f\u00e9\u2603\U0001F600post"
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
        for piece in ("\\u0000", "\\b", "\\f", "\\u001f", "\\u00e9", "\\u2603",
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
    put_secrets(client, {"V": VAR_VALUE, "L": LOGIN, "P": PASSKEY})
    assert opened == []


# -- no secret in logs or output ------------------------------------------------

def test_no_secret_value_appears_in_logs_or_tool_output(client, workspace, caplog, capfd):
    caplog.set_level(logging.DEBUG)
    body = {"V": VAR_VALUE, "L": {**LOGIN, "totp": "JBSWY3DPEHPK3PXP"}, "P": PASSKEY}
    seen = [put_secrets(client, body).text]
    secrets = [VAR_VALUE, PASSWORD, USERNAME, KEY, CRED_ID, HANDLE, "JBSWY3DPEHPK3PXP"]
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


# -- passkeys: authenticator -------------------------------------------------------

def test_passkey_is_loaded_into_the_virtual_authenticator_of_every_tab(make):
    fake, client = make(["https://example.com", "https://other.test"])
    with client:
        put_secrets(client, {"P": PASSKEY})
        assert wait_for(lambda: all(len(fake.credentials.get(i, {})) == 1 for i in (0, 1)))
        for index in (0, 1):
            (cred,) = fake.credentials[index].values()
            assert cred["rpId"] == "example.com" and cred["privateKey"] == KEY
            assert cred["credentialId"] == CRED_ID and cred["userHandle"] == HANDLE
            assert cred["isResidentCredential"] is True
        methods = {m for i, m, _ in fake.calls}
        assert {"WebAuthn.enable", "WebAuthn.addVirtualAuthenticator"} <= methods
        options = next(p for _, m, p in fake.calls if m == "WebAuthn.addVirtualAuthenticator")
        assert options["options"]["automaticPresenceSimulation"] is True


def test_a_tab_opened_later_gets_the_authenticator_too(make):
    fake, client = make(["https://example.com"])
    with client:
        put_secrets(client, {"P": PASSKEY})
        assert wait_for(lambda: len(fake.credentials.get(0, {})) == 1)
        fake.origins.append("https://second.test")
        assert wait_for(lambda: len(fake.credentials.get(1, {})) == 1, 8)


def test_replacing_the_set_removes_a_dropped_passkey(make):
    fake, client = make(["https://example.com"])
    with client:
        put_secrets(client, {"P": PASSKEY})
        assert wait_for(lambda: len(fake.credentials.get(0, {})) == 1)
        put_secrets(client, {"V": VAR_VALUE})
        assert wait_for(lambda: fake.credentials[0] == {})


# -- passkeys: registration arming ----------------------------------------------

def arm(client, rp="example.com"):
    return client.put("/passkeys/registration", content=json.dumps({"rpId": rp}),
                      headers=AUTH)


def status(client):
    r = client.get("/passkeys/registration", headers=AUTH)
    assert r.status_code == 200
    return r.json()


def test_registration_routes_need_bearer(client):
    for method, path in (("put", "/passkeys/registration"), ("get", "/passkeys/registration"),
                         ("delete", "/passkeys/registration"),
                         ("post", "/passkeys/registration/answer")):
        assert getattr(client, method)(path).status_code == 401


def test_arm_validates_rp_id(client):
    for body in ({}, {"rpId": ""}, {"rpId": "a b"}, {"rpId": 5}, {"rpId": "https://a.com"}):
        r = client.put("/passkeys/registration", content=json.dumps(body), headers=AUTH)
        assert r.status_code == 400
    assert status(client) == {"status": "idle"}


def test_arming_parks_create_and_get_answers_asked(make):
    fake, client = make(["https://example.com"])
    with client:
        r = arm(client)
        assert r.status_code == 200 and r.json()["status"] == "armed"
        assert r.json()["rpId"] == "example.com"
        assert wait_for(lambda: 0 in fake.sockets)
        fake.page_calls_create(0, rpId="example.com", rpName="Example",
                               userName="alice", userDisplayName="Alice A")
        assert wait_for(lambda: status(client)["status"] == "asked")
        got = status(client)
        ask = got["ask"]
        assert ask["rpId"] == "example.com" and ask["origin"] == "https://example.com"
        assert ask["rpName"] == "Example" and ask["userName"] == "alice"
        assert ask["userDisplayName"] == "Alice A" and ask["id"] and ask["askedAt"]
        assert fake.release_modes() == []  # parked: the page still waits


def test_approve_mints_and_get_answers_registered_with_the_passkey(make):
    fake, client = make(["https://example.com"])
    with client:
        arm(client)
        assert wait_for(lambda: 0 in fake.sockets)
        fake.page_calls_create(0, rpId="example.com", userName="alice")
        assert wait_for(lambda: status(client)["status"] == "asked")
        ask_id = status(client)["ask"]["id"]
        wrong = client.post("/passkeys/registration/answer", headers=AUTH,
                            content=json.dumps({"id": "nope", "approved": True}))
        assert wrong.status_code == 409
        r = client.post("/passkeys/registration/answer", headers=AUTH,
                        content=json.dumps({"id": ask_id, "approved": True}))
        assert r.status_code == 200 and r.json()["status"] == "approved"
        assert wait_for(lambda: fake.release_modes() == ["allow"])
        # a second answer to a request no longer waiting is a 409
        again = client.post("/passkeys/registration/answer", headers=AUTH,
                            content=json.dumps({"id": ask_id, "approved": False}))
        assert again.status_code == 409
        minted = fake.mint(0)
        assert wait_for(lambda: status(client)["status"] == "registered")
        passkey = status(client)["passkey"]
        assert passkey["kind"] == "passkey" and passkey["rpId"] == "example.com"
        assert passkey["credentialId"] == minted["credentialId"]
        assert passkey["privateKey"] == KEY and passkey["userName"] == "alice"
        # kept in the authenticator until the desk has taken it and disarms
        time.sleep(1.5)
        assert minted["credentialId"] in fake.credentials[0]
        assert client.delete("/passkeys/registration", headers=AUTH).status_code == 200
        assert status(client) == {"status": "idle"}


def test_denied_gives_not_allowed_and_ends_the_arming(make):
    fake, client = make(["https://example.com"])
    with client:
        arm(client)
        assert wait_for(lambda: 0 in fake.sockets)
        fake.page_calls_create(0, rpId="example.com")
        assert wait_for(lambda: status(client)["status"] == "asked")
        r = client.post("/passkeys/registration/answer", headers=AUTH,
                        content=json.dumps({"id": status(client)["ask"]["id"],
                                            "approved": False}))
        assert r.status_code == 200
        assert wait_for(lambda: fake.release_modes() == ["deny"])
        assert status(client) == {"status": "idle"}


def test_not_armed_create_is_not_parked(make):
    fake, client = make(["https://example.com"])
    with client:
        put_secrets(client, {})  # starts the watcher and the tabs
        assert wait_for(lambda: 0 in fake.sockets)
        fake.page_calls_create(0, rpId="example.com")
        assert wait_for(lambda: fake.release_modes() == ["deny"])
        assert status(client) == {"status": "idle"}


def test_create_for_another_site_is_not_parked(make):
    fake, client = make(["https://other.test"])
    with client:
        arm(client, "example.com")
        assert wait_for(lambda: 0 in fake.sockets)
        fake.page_calls_create(0, rpId="other.test")
        assert wait_for(lambda: fake.release_modes() == ["deny"])
        assert status(client)["status"] == "armed"


def test_create_claiming_a_foreign_rp_id_is_not_parked(make):
    fake, client = make(["https://evil.test"])
    with client:
        arm(client, "example.com")
        assert wait_for(lambda: 0 in fake.sockets)
        fake.page_calls_create(0, rpId="example.com")  # origin is not example.com
        assert wait_for(lambda: fake.release_modes() == ["deny"])
        assert status(client)["status"] == "armed"


def test_expired_arming_does_not_park(make):
    now = [1000.0]
    fake, client = make(["https://example.com"], clock=lambda: now[0])
    with client:
        arm(client)
        assert wait_for(lambda: 0 in fake.sockets)
        now[0] += passkeys_module.ARM_SECONDS + 1
        assert status(client) == {"status": "idle"}
        fake.page_calls_create(0, rpId="example.com")
        assert wait_for(lambda: fake.release_modes() == ["deny"])
        assert status(client) == {"status": "idle"}


def test_arming_expiry_releases_a_parked_request(make):
    now = [1000.0]
    fake, client = make(["https://example.com"], clock=lambda: now[0])
    with client:
        arm(client)
        assert wait_for(lambda: 0 in fake.sockets)
        fake.page_calls_create(0, rpId="example.com")
        assert wait_for(lambda: status(client)["status"] == "asked")
        now[0] += passkeys_module.ARM_SECONDS + 1
        assert wait_for(lambda: fake.release_modes() == ["deny"])
        assert status(client) == {"status": "idle"}
        late = client.post("/passkeys/registration/answer", headers=AUTH,
                           content=json.dumps({"id": "x", "approved": True}))
        assert late.status_code == 409


def test_a_credential_minted_without_approval_is_removed(make):
    fake, client = make(["https://example.com"])
    with client:
        put_secrets(client, {})
        assert wait_for(lambda: 0 in fake.sockets)
        minted = fake.mint(0)  # not armed
        assert wait_for(lambda: minted["credentialId"] not in fake.credentials[0])
        arm(client)
        minted = fake.mint(0, ident=b"armed-but-not-asked")  # armed, never approved
        assert wait_for(lambda: minted["credentialId"] not in fake.credentials[0])
        assert status(client)["status"] == "armed"


def test_a_credential_for_another_site_after_approval_is_removed(make):
    fake, client = make(["https://example.com"])
    with client:
        arm(client)
        assert wait_for(lambda: 0 in fake.sockets)
        fake.page_calls_create(0, rpId="example.com")
        assert wait_for(lambda: status(client)["status"] == "asked")
        client.post("/passkeys/registration/answer", headers=AUTH,
                    content=json.dumps({"id": status(client)["ask"]["id"], "approved": True}))
        minted = fake.mint(0, rp_id="other.test")
        assert wait_for(lambda: minted["credentialId"] not in fake.credentials[0])
        assert status(client)["status"] == "approved"


def _approve(client, fake, **ask):
    arm(client)
    assert wait_for(lambda: 0 in fake.sockets)
    fake.page_calls_create(0, rpId="example.com", **ask)
    assert wait_for(lambda: status(client)["status"] == "asked")
    client.post("/passkeys/registration/answer", headers=AUTH,
                content=json.dumps({"id": status(client)["ask"]["id"], "approved": True}))
    assert wait_for(lambda: status(client)["status"] == "approved")


OTHER_HANDLE = base64.b64encode(b"someone-else").decode()


def test_a_second_credential_while_approved_is_removed_and_not_reported(make):
    fake, client = make(["https://example.com"])
    with client:
        _approve(client, fake, userId=HANDLE)
        stray = fake.mint(0, ident=b"stray-credential", handle=OTHER_HANDLE)
        assert wait_for(lambda: stray["credentialId"] not in fake.credentials[0])
        assert status(client)["status"] == "approved"
        minted = fake.mint(0, ident=b"the-real-credential")
        assert wait_for(lambda: status(client)["status"] == "registered")
        assert status(client)["passkey"]["credentialId"] == minted["credentialId"]
        assert minted["credentialId"] in fake.credentials[0]


def test_a_credential_after_the_approved_one_is_removed(make):
    fake, client = make(["https://example.com"])
    with client:
        _approve(client, fake, userId=HANDLE)
        minted = fake.mint(0, ident=b"the-real-credential")
        assert wait_for(lambda: status(client)["status"] == "registered")
        late = fake.mint(0, ident=b"late-credential", handle=OTHER_HANDLE)
        assert wait_for(lambda: late["credentialId"] not in fake.credentials[0])
        assert status(client)["passkey"]["credentialId"] == minted["credentialId"]


def test_a_look_during_approval_removes_an_unrelated_credential(make):
    fake, client = make(["https://example.com"])
    with client:
        _approve(client, fake, userId=HANDLE)
        stray = {"credentialId": base64.b64encode(b"planted").decode(),
                 "rpId": "example.com", "isResidentCredential": True,
                 "privateKey": KEY, "userHandle": OTHER_HANDLE, "signCount": 0}
        fake.credentials[0][stray["credentialId"]] = stray  # no event: only a look finds it
        assert wait_for(lambda: stray["credentialId"] not in fake.credentials[0], 6)
        assert status(client)["status"] == "approved"


def test_minted_key_is_redacted_from_tool_output(make, workspace):
    fake, client = make(["https://example.com"])
    with client:
        arm(client)
        assert wait_for(lambda: 0 in fake.sockets)
        fake.page_calls_create(0, rpId="example.com")
        assert wait_for(lambda: status(client)["status"] == "asked")
        client.post("/passkeys/registration/answer", headers=AUTH,
                    content=json.dumps({"id": status(client)["ask"]["id"], "approved": True}))
        fake.mint(0)
        assert wait_for(lambda: status(client)["status"] == "registered")
        (workspace / "k.txt").write_text(KEY)
        out = answer(call(client, "files", {"action": "read", "path": "k.txt"}))
        assert out["content"] == "[REDACTED]"


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
