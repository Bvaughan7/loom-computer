"""Passkeys: a WebAuthn virtual authenticator on every browser tab, and the
guard that parks a site's `navigator.credentials.create()` while the person
has armed the computer for that site.

A virtual authenticator lives only as long as the DevTools socket that made
it, so each tab keeps one long-lived socket here (the tools' own sockets stay
short). Per tab: the authenticator, the granted passkeys loaded into it, a
page script that wraps `create()`, and a binding the script reports through.

What is enforced, and where:

* The page script parks `create()` and reports it; this module decides. Not
  armed, another site, another origin, or a second request: the site gets a
  `NotAllowedError` and nothing is minted.
* An approval is bound to the one parked ceremony: its tab, its rpId and the
  user handle the page asked to register. Only a credential that matches is
  taken; any other, even while the approval is in flight, is removed at once.
* The page script is the first line only. A credential that appears in an
  authenticator without an approval for this very arming, or for another site,
  or after the ten minutes, is removed (on its event and on every look).
"""

import asyncio
import json
import logging
import re
import secrets as _random
import time
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .secrets import SecretStore, b64_bytes, b64_std

log = logging.getLogger("loom_computer")

ARM_SECONDS = 600
POLL_SECONDS = 1.0
CALL_TIMEOUT = 10.0
BINDING = "__loomPasskeyAsk"
_RP_ID = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?\Z")

_GUARD = """(binding, nonce) => {
  const proto = window.CredentialsContainer && CredentialsContainer.prototype;
  const ask = window[binding];
  if (!proto || typeof ask !== 'function' || typeof proto.create !== 'function') return;
  const original = proto.create;
  const originalGet = proto.get;
  const pending = new Map();
  const newId = () => Array.from(crypto.getRandomValues(new Uint8Array(16)),
                                 (b) => b.toString(16).padStart(2, '0')).join('');
  const b64 = (v) => { try {
    const u = v instanceof ArrayBuffer ? new Uint8Array(v)
      : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    return btoa(String.fromCharCode(...u)).slice(0, 400);
  } catch (e) { return null; } };
  const text = (v) => { try { return v == null ? null : String(v).slice(0, 200); } catch (e) { return null; } };
  const guarded = function create(options) {
    if (!options || !options.publicKey) return original.apply(this, arguments);
    const self = this, args = arguments, pk = options.publicKey;
    return new Promise((resolve, reject) => {
      const id = newId();
      pending.set(id, {resolve, reject, run: () => original.apply(self, args)});
      let rp = {}, user = {};
      try { rp = pk.rp || {}; user = pk.user || {}; } catch (e) {}
      ask(JSON.stringify({id, rpId: text(rp.id), rpName: text(rp.name),
                          userName: text(user.name), userId: b64(user.id),
                          userDisplayName: text(user.displayName)}));
    });
  };
  // A sign-in waits for the computer to confirm the authenticator is in
  // place (a navigation can drop it); if nobody answers, it goes ahead.
  const guardedGet = function get(options) {
    if (!options || !options.publicKey || typeof originalGet !== 'function')
      return originalGet.apply(this, arguments);
    const self = this, args = arguments;
    return new Promise((resolve, reject) => {
      const id = newId();
      const entry = {resolve, reject, run: () => originalGet.apply(self, args)};
      pending.set(id, entry);
      setTimeout(() => { if (pending.delete(id)) entry.run().then(resolve, reject); }, 8000);
      ask(JSON.stringify({id, kind: 'get'}));
    });
  };
  const release = (id, given, mode) => {
    if (given !== nonce) return false;
    const entry = pending.get(id);
    if (!entry) return false;
    pending.delete(id);
    if (mode === 'allow') entry.run().then(entry.resolve, entry.reject);
    else entry.reject(new DOMException(
      'The operation either timed out or was not allowed.', 'NotAllowedError'));
    return true;
  };
  Object.defineProperty(proto, 'create', {value: guarded, configurable: true, writable: true});
  if (typeof originalGet === 'function')
    Object.defineProperty(proto, 'get', {value: guardedGet, configurable: true, writable: true});
  try { Object.defineProperty(window, '__loomRelease',
        {value: release, configurable: false, writable: false}); } catch (e) {}
}"""


def _clip(value) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return re.sub(r"[\x00-\x1f\x7f]", "?", value)[:200]


def valid_rp_id(value) -> bool:
    return isinstance(value, str) and len(value) <= 253 and bool(_RP_ID.match(value))


class _Conn:
    """One DevTools socket, many calls in flight, events handed to a callback."""

    def __init__(self, socket, on_event):
        self._socket = socket
        self._on_event = on_event
        self._next = 0
        self._waiting: dict[int, asyncio.Future] = {}

    async def call(self, method: str, params: dict | None = None) -> dict:
        self._next += 1
        ident = self._next
        waiter = asyncio.get_running_loop().create_future()
        self._waiting[ident] = waiter
        try:
            await self._socket.send(json.dumps(
                {"id": ident, "method": method, "params": params or {}}))
            return await asyncio.wait_for(waiter, CALL_TIMEOUT)
        finally:
            self._waiting.pop(ident, None)

    async def run(self) -> None:
        try:
            async for raw in self._socket:
                message = json.loads(raw)
                waiter = self._waiting.get(message.get("id"))
                if waiter is not None and not waiter.done():
                    if "error" in message:
                        waiter.set_exception(RuntimeError(
                            str(message["error"].get("message", "error"))))
                    else:
                        waiter.set_result(message.get("result", {}))
                elif "method" in message:
                    self._on_event(message)
        except Exception:  # noqa: BLE001 - a dying socket just ends the tab
            pass
        finally:
            for waiter in self._waiting.values():
                if not waiter.done():
                    waiter.set_exception(ConnectionError("tab closed"))

    async def close(self) -> None:
        try:
            await self._socket.close()
        except Exception:  # noqa: BLE001
            pass


@dataclass
class _Tab:
    target: str
    conn: _Conn
    nonce: str
    authenticator: str = ""
    reader: asyncio.Task | None = None
    background: set = field(default_factory=set)
    closed: bool = False


@dataclass
class _Registration:
    rp_id: str
    expires: float
    status: str = "armed"  # armed -> asked -> approved -> registered
    ask: dict | None = None
    parked: tuple | None = None  # (tab, execution context id, page-side id)
    user_handle: bytes | None = None  # the user.id the parked ceremony registers
    passkey: dict | None = None


class Passkeys:
    def __init__(self, store: SecretStore, endpoint: str, clock=time.time):
        self._store = store
        self._endpoint = endpoint
        self._clock = clock
        self._tabs: dict[str, _Tab] = {}
        self._reg: _Registration | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._runner: asyncio.Task | None = None
        self._attach_lock: asyncio.Lock | None = None
        store.on_change(self._secrets_changed)

    # -- lifecycle ------------------------------------------------------------

    def start(self) -> None:
        """Begin watching tabs. Idempotent; a new event loop starts over."""
        loop = asyncio.get_running_loop()
        if self._loop is loop and self._runner and not self._runner.done():
            return
        self._tabs.clear()
        self._loop, self._attach_lock = loop, asyncio.Lock()
        self._runner = loop.create_task(self._watch())

    async def stop(self) -> None:
        runner, self._runner = self._runner, None
        if runner:
            runner.cancel()
            await asyncio.gather(runner, return_exceptions=True)
        for tab in list(self._tabs.values()):
            await self._close_tab(tab)

    async def _watch(self) -> None:
        while True:
            try:
                await self.attach_all()
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.debug("passkey watcher pass failed", exc_info=True)
            await asyncio.sleep(POLL_SECONDS)

    def _secrets_changed(self) -> None:
        # Sync soon rather than inline: the setter may be a sync caller.
        if self._loop and self._runner and not self._runner.done():
            self._loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(self._tick()))

    # -- tabs -----------------------------------------------------------------

    def _list_targets(self, create: bool) -> list[dict]:
        def fetch(url: str, method: str = "GET") -> bytes:
            request = urllib.request.Request(url, method=method)
            with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - loopback
                return response.read()

        pages = [t for t in json.loads(fetch(f"{self._endpoint}/json/list"))
                 if t.get("type") == "page" and t.get("webSocketDebuggerUrl")
                 and not t.get("url", "").startswith("devtools:")]
        if not pages and create:
            pages = [json.loads(fetch(f"{self._endpoint}/json/new?about:blank", "PUT"))]
        return pages

    async def attach_all(self, create: bool = False) -> None:
        """Every open tab gets its authenticator before this returns."""
        if self._attach_lock is None or self._loop is not asyncio.get_running_loop():
            self.start()
        async with self._attach_lock:
            try:
                pages = await asyncio.to_thread(self._list_targets, create)
            except (OSError, ValueError):
                return
            live = {p["webSocketDebuggerUrl"] for p in pages}
            for target in [t for t in self._tabs if t not in live or self._tabs[t].closed]:
                await self._close_tab(self._tabs[target])
            for page in pages:
                if page["webSocketDebuggerUrl"] not in self._tabs:
                    try:
                        await self._open_tab(page)
                    except Exception:  # noqa: BLE001 - try again on the next pass
                        log.debug("could not ready a tab", exc_info=True)

    async def _open_tab(self, page: dict) -> None:
        from websockets.asyncio.client import connect

        socket = await connect(page["webSocketDebuggerUrl"], max_size=16 * 1024 * 1024,
                               open_timeout=5, ping_interval=None, compression=None)
        tab = _Tab(page["webSocketDebuggerUrl"], None, _random.token_hex(24))  # type: ignore[arg-type]
        tab.conn = _Conn(socket, lambda message: self._event(tab, message))
        tab.reader = asyncio.ensure_future(tab.conn.run())
        tab.reader.add_done_callback(lambda _t: setattr(tab, "closed", True))
        try:
            await self._setup_authenticator(tab, load=False)
            await tab.conn.call("Runtime.enable")
            await tab.conn.call("Runtime.addBinding", {"name": BINDING})
            await tab.conn.call("Page.enable")
            source = f"({_GUARD})({json.dumps(BINDING)}, {json.dumps(tab.nonce)})"
            await tab.conn.call("Page.addScriptToEvaluateOnNewDocument", {"source": source})
            await tab.conn.call("Runtime.evaluate", {"expression": source})
            self._tabs[tab.target] = tab
            await self._sync(tab)
        except BaseException:
            self._tabs.pop(tab.target, None)
            await self._close_tab(tab)
            raise

    async def _setup_authenticator(self, tab: _Tab, load: bool = True) -> None:
        """(Re)create the tab's virtual authenticator. A navigation to another
        process drops the WebAuthn domain's state on the browser side, so this
        runs again whenever a look finds it gone."""
        try:  # a stale "enabled" flag must not turn the enable below into a no-op
            await tab.conn.call("WebAuthn.disable")
        except RuntimeError:
            pass
        await tab.conn.call("WebAuthn.enable", {"enableUI": False})
        added = await tab.conn.call("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "internal",
            "hasResidentKey": True, "hasUserVerification": True,
            "isUserVerified": True, "automaticPresenceSimulation": True}})
        tab.authenticator = added["authenticatorId"]
        if load:
            await self._sync(tab)

    async def _ensure(self, tab: _Tab) -> None:
        """The tab can answer a sign-in right now, and its page is focused.

        Right after a navigation commits the domain can be reset once more
        behind our back, so a failed look is retried a few times."""
        for attempt in range(8):
            try:
                await tab.conn.call("WebAuthn.getCredentials",
                                    {"authenticatorId": tab.authenticator})
                break
            except RuntimeError as exc:
                log.debug("authenticator look %d failed: %s", attempt, exc)
                try:
                    await self._setup_authenticator(tab)
                    log.debug("authenticator set up again")
                    break
                except RuntimeError as again:
                    log.debug("set up failed: %s", again)
                    await asyncio.sleep(0.25)
        await self._focus(tab)

    async def _settle(self, tab: _Tab, context: int) -> None:
        """Before a ceremony is handed to the browser: the document has
        finished loading and the authenticator has survived it. The browser
        drops the WebAuthn domain's state around a navigation's load, and a
        ceremony started before that is orphaned, waiting forever."""
        for _ in range(25):
            try:
                ready = await tab.conn.call("Runtime.evaluate", {
                    "expression": "document.readyState", "contextId": context,
                    "returnByValue": True})
            except RuntimeError:
                break  # the context is gone: the page moved on
            if ready.get("result", {}).get("value") == "complete":
                break
            await asyncio.sleep(0.2)
        await self._ensure(tab)
        await asyncio.sleep(0.3)
        await self._ensure(tab)

    async def _close_tab(self, tab: _Tab) -> None:
        self._tabs.pop(tab.target, None)
        tab.closed = True
        for task in list(tab.background):
            task.cancel()
        await tab.conn.close()
        if tab.reader:
            tab.reader.cancel()
        reg = self._reg
        if reg and reg.parked and reg.parked[0] is tab and reg.status == "asked":
            reg.status, reg.ask, reg.parked = "armed", None, None

    # -- authenticator contents -----------------------------------------------

    def _protected(self) -> set[bytes]:
        reg = self._reg
        if reg and reg.status == "registered" and reg.passkey:
            return {b64_bytes(reg.passkey["credentialId"])}
        return set()

    def _is_ceremony(self, tab: _Tab, credential: dict) -> bool:
        """The credential is the one the approved, parked ceremony mints."""
        reg = self._reg
        if (reg is None or reg.status != "approved" or not reg.parked
                or reg.parked[0] is not tab or credential.get("rpId") != reg.rp_id
                or not credential.get("privateKey")):
            return False
        if reg.user_handle is not None:
            try:
                handle = b64_bytes(credential.get("userHandle") or "")
            except ValueError:
                return False
            return handle == reg.user_handle
        return True

    async def _sync(self, tab: _Tab) -> None:
        """Make the tab's authenticator hold exactly the granted passkeys
        (plus a just-minted one until the desk has taken it)."""
        got = await tab.conn.call("WebAuthn.getCredentials",
                                  {"authenticatorId": tab.authenticator})
        wanted = {k.key: k for k in self._store.passkeys.values()}
        keep = self._protected()
        # While an approved mint is in flight its event decides, not this look.
        reg = self._reg
        minting = reg is not None and reg.status == "approved"
        present: dict[bytes, dict] = {}
        for credential in got.get("credentials", []):
            ident = b64_bytes(credential["credentialId"])
            record = wanted.get(ident)
            if ident in keep and record is None:
                present[ident] = credential
            elif record is None and minting and self._is_ceremony(tab, credential):
                continue
            elif record is None or credential.get("privateKey") != record.private_key:
                await tab.conn.call("WebAuthn.removeCredential", {
                    "authenticatorId": tab.authenticator,
                    "credentialId": credential["credentialId"]})
            else:
                present[ident] = credential
        for ident, record in wanted.items():
            if ident in present:
                continue
            credential = {"credentialId": record.credential_id,
                          "isResidentCredential": record.user_handle is not None,
                          "rpId": record.rp_id, "privateKey": record.private_key,
                          "signCount": 0}
            if record.user_handle is not None:
                credential["userHandle"] = record.user_handle
            await tab.conn.call("WebAuthn.addCredential", {
                "authenticatorId": tab.authenticator, "credential": credential})

    async def _focus(self, tab: _Tab) -> None:
        """WebAuthn ceremonies wait for a focused page, and nothing in this
        desktop focuses Chromium's window until it is told to. Only the tab
        already showing is brought forward, so no tab is switched."""
        shown = await tab.conn.call("Runtime.evaluate", {
            "expression": "[document.visibilityState, document.hasFocus()]",
            "returnByValue": True})
        state = shown.get("result", {}).get("value")
        if state == ["visible", False]:
            await tab.conn.call("Page.bringToFront")

    async def _tick(self) -> None:
        self._expire()
        wanted = bool(self._store.passkeys) or self._reg is not None
        for tab in list(self._tabs.values()):
            if tab.closed:
                continue
            try:
                if wanted:
                    await self._ensure(tab)
                await self._sync(tab)
            except Exception:  # noqa: BLE001
                log.debug("passkey look failed; the tab is attached afresh", exc_info=True)
                await self._close_tab(tab)

    # -- events from a tab ----------------------------------------------------

    def _event(self, tab: _Tab, message: dict) -> None:
        method, params = message.get("method"), message.get("params", {})
        if method in ("Page.frameNavigated", "Page.loadEventFired", "Page.frameStartedLoading",
                      "Runtime.executionContextsCleared"):
            log.debug("tab event %s", method)
        if method == "Runtime.bindingCalled" and params.get("name") == BINDING:
            work = self._on_ask(tab, params)
        elif method == "WebAuthn.credentialAdded":
            work = self._on_credential(tab, params.get("credential", {}))
        else:
            return
        task = asyncio.ensure_future(work)
        tab.background.add(task)
        task.add_done_callback(tab.background.discard)

    async def _release(self, tab: _Tab, context: int, ident: str, mode: str) -> None:
        expression = (f"window.__loomRelease && window.__loomRelease("
                      f"{json.dumps(ident)}, {json.dumps(tab.nonce)}, {json.dumps(mode)})")
        try:
            await tab.conn.call("Runtime.evaluate",
                                {"expression": expression, "contextId": context})
        except Exception:  # noqa: BLE001 - the page navigated away: nothing waits
            pass

    async def _on_ask(self, tab: _Tab, params: dict) -> None:
        context = params.get("executionContextId")
        try:
            raw = json.loads(params.get("payload", ""))
            ident = raw["id"]
            if not isinstance(ident, str) or not re.fullmatch(r"[0-9a-f]{32}", ident):
                return
            if raw.get("kind") == "get":
                log.debug("sign-in asked")
                try:
                    await self._settle(tab, context)
                except Exception:  # noqa: BLE001 - the sign-in goes ahead regardless
                    log.debug("could not ready a sign-in", exc_info=True)
                log.debug("sign-in released")
                await self._release(tab, context, ident, "allow")
                return
            where = await tab.conn.call("Runtime.evaluate", {
                "expression": "location.origin", "contextId": context,
                "returnByValue": True})
            origin = where.get("result", {}).get("value")
        except Exception:  # noqa: BLE001
            return
        self._expire()
        reg = self._reg
        asked = None
        if reg is not None and reg.status == "armed" and isinstance(origin, str):
            host = (urlsplit(origin).hostname or "").lower()
            rp_id = (_clip(raw.get("rpId")) or host).lower()
            secure = origin.startswith("https://") or host in ("localhost", "127.0.0.1")
            if (rp_id == reg.rp_id and secure
                    and (host == rp_id or host.endswith("." + rp_id))):
                asked = {"id": _random.token_hex(16), "rpId": rp_id, "origin": origin,
                         "askedAt": int(self._clock() * 1000)}
                for key in ("rpName", "userName", "userDisplayName"):
                    if _clip(raw.get(key)):
                        asked[key] = _clip(raw[key])
                reg.status, reg.ask, reg.parked = "asked", asked, (tab, context, ident)
                reg.user_handle = None
                if isinstance(raw.get("userId"), str) and raw["userId"]:
                    try:
                        reg.user_handle = b64_bytes(raw["userId"])
                    except ValueError:
                        pass
        if asked is None:
            await self._release(tab, context, ident, "deny")

    async def _on_credential(self, tab: _Tab, credential: dict) -> None:
        try:
            ident = b64_bytes(credential.get("credentialId", ""))
        except ValueError:
            ident = b""
        if ident and any(k.key == ident for k in self._store.passkeys.values()):
            return  # one the desk granted, loaded by us
        self._expire()
        reg = self._reg
        if reg is not None and self._is_ceremony(tab, credential):
            record = {"kind": "passkey", "rpId": reg.rp_id,
                      "credentialId": b64_std(credential["credentialId"]),
                      "privateKey": b64_std(credential["privateKey"])}
            if credential.get("userHandle"):
                record["userHandle"] = b64_std(credential["userHandle"])
            for key in ("userName", "userDisplayName"):
                if reg.ask and reg.ask.get(key):
                    record[key] = reg.ask[key]
            self._store.remember(record["privateKey"])
            reg.status, reg.passkey, reg.parked = "registered", record, None
            return
        try:
            await tab.conn.call("WebAuthn.removeCredential", {
                "authenticatorId": tab.authenticator,
                "credentialId": credential.get("credentialId", "")})
        except Exception:  # noqa: BLE001
            pass  # the next look removes it

    # -- the registration arming ----------------------------------------------

    def _expire(self) -> None:
        reg = self._reg
        if reg is None or reg.status == "registered" or self._clock() < reg.expires:
            return
        parked, self._reg = reg.parked, None
        if parked and self._loop:
            tab, context, ident = parked
            asyncio.ensure_future(self._release(tab, context, ident, "deny"))

    async def arm(self, rp_id: str) -> dict:
        await self._cancel_parked()
        self._reg = _Registration(rp_id, self._clock() + ARM_SECONDS)
        await self.attach_all(create=True)  # ready the browser
        return self.status()

    async def disarm(self) -> None:
        await self._cancel_parked()
        self._reg = None

    async def _cancel_parked(self) -> None:
        reg = self._reg
        if reg and reg.parked and reg.status == "asked":
            await self._release(*reg.parked, "deny")

    def status(self) -> dict:
        self._expire()
        reg = self._reg
        if reg is None:
            return {"status": "idle"}
        out = {"status": reg.status, "rpId": reg.rp_id,
               "expiresAt": int(reg.expires * 1000)}
        if reg.status == "asked":
            out["ask"] = reg.ask
        if reg.status == "registered":
            out["passkey"] = reg.passkey
        return out

    async def answer(self, ident, approved: bool) -> bool:
        """False when no such request is waiting (the route answers 409)."""
        self._expire()
        reg = self._reg
        if reg is None or reg.status != "asked" or not reg.ask or reg.ask["id"] != ident:
            return False
        if approved:
            reg.status = "approved"
            tab, context, ident = reg.parked
            try:
                await self._settle(tab, context)
            except Exception:  # noqa: BLE001 - the page's create() goes ahead regardless
                log.debug("could not ready a registration", exc_info=True)
            await self._release(tab, context, ident, "allow")
        else:
            parked, self._reg = reg.parked, None
            await self._release(*parked, "deny")
        return True
