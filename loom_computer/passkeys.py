"""Passkeys: a WebAuthn virtual authenticator on every browser tab, loaded
with the granted passkeys so a site's `navigator.credentials.get()` is
answered without anything typed.

A virtual authenticator lives only as long as the DevTools socket that made
it, so each tab keeps one long-lived socket here (the tools' own sockets stay
short). Per tab: the authenticator, and the granted passkeys loaded into it.
Every look makes the authenticator hold exactly the granted set: a credential
that appears there and was not granted is removed, on its event and on every
look.

There is no registration: nothing here mints a passkey.
"""

import asyncio
import json
import logging
import urllib.request
from dataclasses import dataclass, field

from .secrets import SecretStore, b64_bytes

log = logging.getLogger("loom_computer")

POLL_SECONDS = 1.0
CALL_TIMEOUT = 10.0


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
    authenticator: str = ""
    reader: asyncio.Task | None = None
    background: set = field(default_factory=set)
    closed: bool = False


class Passkeys:
    def __init__(self, store: SecretStore, endpoint: str):
        self._store = store
        self._endpoint = endpoint
        self._tabs: dict[str, _Tab] = {}
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

    def _list_targets(self) -> list[dict]:
        def fetch(url: str) -> bytes:
            with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - loopback
                return response.read()

        return [t for t in json.loads(fetch(f"{self._endpoint}/json/list"))
                if t.get("type") == "page" and t.get("webSocketDebuggerUrl")
                and not t.get("url", "").startswith("devtools:")]

    async def attach_all(self) -> None:
        """Every open tab gets its authenticator before this returns."""
        if self._attach_lock is None or self._loop is not asyncio.get_running_loop():
            self.start()
        async with self._attach_lock:
            try:
                pages = await asyncio.to_thread(self._list_targets)
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
        tab = _Tab(page["webSocketDebuggerUrl"], None)  # type: ignore[arg-type]
        tab.conn = _Conn(socket, lambda message: self._event(tab, message))
        tab.reader = asyncio.ensure_future(tab.conn.run())
        tab.reader.add_done_callback(lambda _t: setattr(tab, "closed", True))
        try:
            await self._setup_authenticator(tab, load=False)
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

    async def _close_tab(self, tab: _Tab) -> None:
        self._tabs.pop(tab.target, None)
        tab.closed = True
        for task in list(tab.background):
            task.cancel()
        await tab.conn.close()
        if tab.reader:
            tab.reader.cancel()

    # -- authenticator contents -----------------------------------------------

    async def _sync(self, tab: _Tab) -> None:
        """Make the tab's authenticator hold exactly the granted passkeys."""
        got = await tab.conn.call("WebAuthn.getCredentials",
                                  {"authenticatorId": tab.authenticator})
        wanted = {k.key: k for k in self._store.passkeys.values()}
        present: dict[bytes, dict] = {}
        for credential in got.get("credentials", []):
            ident = b64_bytes(credential["credentialId"])
            record = wanted.get(ident)
            if record is None or credential.get("privateKey") != record.private_key:
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
        wanted = bool(self._store.passkeys)
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
        if message.get("method") != "WebAuthn.credentialAdded":
            return
        task = asyncio.ensure_future(
            self._on_credential(tab, message.get("params", {}).get("credential", {})))
        tab.background.add(task)
        task.add_done_callback(tab.background.discard)

    async def _on_credential(self, tab: _Tab, credential: dict) -> None:
        try:
            ident = b64_bytes(credential.get("credentialId", ""))
        except ValueError:
            ident = b""
        if ident and any(k.key == ident for k in self._store.passkeys.values()):
            return  # one the desk granted, loaded by us
        try:
            await tab.conn.call("WebAuthn.removeCredential", {
                "authenticatorId": tab.authenticator,
                "credentialId": credential.get("credentialId", "")})
        except Exception:  # noqa: BLE001
            pass  # the next look removes it
