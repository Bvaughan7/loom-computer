"""The real Chromium of the desktop, driven over the Chrome DevTools Protocol.

Chromium is started by supervisord with a debugging port on loopback. Each
call finds the active tab (the page that reports itself focused, else
visible, over CDP), opens a socket to it, does its work, and closes: nothing
is cached, so a tab the person opened, closed or switched to in the viewer is
simply what the next call finds.
"""

import asyncio
import json
import os
import urllib.request

from .errors import ToolError

DEFAULT_ENDPOINT = "http://127.0.0.1:9222"
NAVIGATE_TIMEOUT = 30.0
CALL_TIMEOUT = 15.0
MAX_TEXT = 100_000
MAX_TREE_LINES = 2000
MAX_TREE_BYTES = 200_000
MAX_TREE_FIELD = 500  # characters of one node name or value
SCHEMES = ("http:", "https:", "file:", "about:", "data:")

_FILL = """(selector, value) => {
  const el = document.querySelector(selector);
  if (!el) return {error: 'no element matches the selector'};
  el.scrollIntoView({block: 'center'});
  el.focus();
  const fire = (type) => el.dispatchEvent(new Event(type, {bubbles: true}));
  if (el.isContentEditable) {
    el.textContent = value; fire('input'); fire('change');
    return {filled: el.tagName.toLowerCase()};
  }
  const tag = el.tagName;
  if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT')
    return {error: 'element is not a form field'};
  if (el.disabled || el.readOnly) return {error: 'field is disabled or read-only'};
  const proto = tag === 'INPUT' ? HTMLInputElement.prototype
    : tag === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLSelectElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
  if (tag === 'SELECT' && el.value !== value) return {error: 'no option has that value'};
  fire('input'); fire('change');
  return {filled: tag.toLowerCase()};
}"""

_CENTER = """(selector) => {
  const el = document.querySelector(selector);
  if (!el) return {error: 'no element matches the selector'};
  el.scrollIntoView({block: 'center', inline: 'center'});
  const r = el.getBoundingClientRect();
  if (r.width === 0 || r.height === 0) return {error: 'element has no visible size'};
  return {x: r.left + r.width / 2, y: r.top + r.height / 2};
}"""

_TEXT = """(selector) => {
  const el = selector === null ? document.body : document.querySelector(selector);
  if (!el) return {error: 'no element matches the selector'};
  return {text: el.innerText ?? el.textContent ?? ''};
}"""


def _fetch(url: str, method: str = "GET") -> bytes:
    request = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - loopback
        return response.read()


class _Session:
    """One CDP socket: commands in order, events kept for `wait_event`."""

    def __init__(self, socket):
        self._socket = socket
        self._next = 0
        self._events: list[dict] = []

    async def call(self, method: str, params: dict | None = None) -> dict:
        self._next += 1
        ident = self._next
        await self._socket.send(json.dumps(
            {"id": ident, "method": method, "params": params or {}}))
        while True:
            message = json.loads(await asyncio.wait_for(self._socket.recv(), CALL_TIMEOUT))
            if message.get("id") == ident:
                if "error" in message:
                    raise ToolError(f"{message['error'].get('message', 'error')}")
                return message.get("result", {})
            if "method" in message:
                self._events.append(message)

    async def wait_event(self, name: str, timeout: float) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            if any(event["method"] == name for event in self._events):
                return True
            left = deadline - asyncio.get_running_loop().time()
            if left <= 0:
                return False
            try:
                message = json.loads(await asyncio.wait_for(self._socket.recv(), left))
            except asyncio.TimeoutError:
                return False
            if "method" in message:
                self._events.append(message)

    async def evaluate(self, function: str, *args):
        """Run an arrow function with JSON-encoded arguments; its value."""
        expression = f"({function})({', '.join(json.dumps(a) for a in args)})"
        result = await self.call("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": True})
        if "exceptionDetails" in result:
            details = result["exceptionDetails"]
            text = details.get("exception", {}).get("description") or details.get("text", "")
            raise ToolError(f"page script failed: {text.splitlines()[0] if text else 'error'}")
        value = result.get("result", {}).get("value")
        if isinstance(value, dict) and "error" in value:
            raise ToolError(f"{value['error']}")
        return value


class Browser:
    def __init__(self, endpoint: str | None = None):
        self.endpoint = endpoint or os.environ.get("LOOM_CDP_ENDPOINT", DEFAULT_ENDPOINT)
        self._lock = asyncio.Lock()

    async def _pages(self) -> list[dict]:
        try:
            raw = await asyncio.to_thread(_fetch, f"{self.endpoint}/json/list")
            pages = [t for t in json.loads(raw)
                     if t.get("type") == "page" and t.get("webSocketDebuggerUrl")
                     and not t.get("url", "").startswith("devtools:")]
            if not pages:
                raw = await asyncio.to_thread(
                    _fetch, f"{self.endpoint}/json/new?about:blank", "PUT")
                pages = [json.loads(raw)]
        except (OSError, ValueError):
            raise ToolError("cannot reach Chromium; the desktop may still "
                            "be starting, try again shortly") from None
        return pages

    async def _probe(self, page: dict) -> int:
        """2 when the page has focus, 1 when merely visible, else 0."""
        from websockets.asyncio.client import connect

        try:
            async with connect(page["webSocketDebuggerUrl"], max_size=1024 * 1024,
                               open_timeout=2, ping_interval=None,
                               compression=None) as socket:
                session = _Session(socket)
                state = await session.evaluate(
                    "() => [document.visibilityState, document.hasFocus()]")
        except Exception:  # noqa: BLE001 - an unprobeable tab is just not preferred
            return 0
        if not isinstance(state, list) or len(state) != 2 or state[0] != "visible":
            return 0
        return 2 if state[1] else 1

    async def _target(self) -> str:
        """The active tab's debugger URL; the first page if none can say."""
        pages = await self._pages()
        if len(pages) > 1:
            ranks = await asyncio.gather(*(self._probe(p) for p in pages))
            best = max(range(len(pages)), key=lambda i: (ranks[i], -i))
            if ranks[best] > 0:
                return pages[best]["webSocketDebuggerUrl"]
        return pages[0]["webSocketDebuggerUrl"]

    async def _with_page(self, work):
        from websockets.asyncio.client import connect
        from websockets.exceptions import WebSocketException

        async with self._lock:
            for attempt in (1, 2):
                url = await self._target()
                started = False
                try:
                    async with connect(url, max_size=64 * 1024 * 1024, open_timeout=5,
                                       ping_interval=None, compression=None) as socket:
                        started = True
                        return await work(_Session(socket))
                except asyncio.TimeoutError:
                    raise ToolError("Chromium did not answer in time") from None
                except (OSError, WebSocketException):
                    # The tab closed between probing and connecting: choose
                    # again among the remaining tabs, once. Work that already
                    # began is never repeated.
                    if started or attempt == 2:
                        raise ToolError("lost the connection to Chromium") from None

    async def navigate(self, url) -> dict:
        if not isinstance(url, str) or not url.lower().startswith(SCHEMES):
            raise ToolError("url must be a string starting with one of: "
                            + ", ".join(s + ("//" if s in ("http:", "https:", "file:") else "")
                                        for s in SCHEMES))

        async def work(page: _Session):
            await page.call("Page.enable")
            result = await page.call("Page.navigate", {"url": url})
            if result.get("errorText"):
                raise ToolError(f"navigation failed: {result['errorText']}")
            loaded = await page.wait_event("Page.loadEventFired", NAVIGATE_TIMEOUT)
            return {"url": await page.evaluate("() => location.href"),
                    "title": await page.evaluate("() => document.title"),
                    "loaded": loaded}
        return await self._with_page(work)

    async def title(self) -> dict:
        async def work(page: _Session):
            return {"url": await page.evaluate("() => location.href"),
                    "title": await page.evaluate("() => document.title")}
        return await self._with_page(work)

    async def text(self, selector=None) -> dict:
        _check_selector(selector, required=False)

        async def work(page: _Session):
            value = await page.evaluate(_TEXT, selector)
            text = value.get("text") if isinstance(value, dict) else None
            text = text if isinstance(text, str) else ""
            return {"text": text[:MAX_TEXT], "truncated": len(text) > MAX_TEXT}
        return await self._with_page(work)

    async def fill(self, selector, value) -> dict:
        _check_selector(selector)
        if not isinstance(value, str):
            raise ToolError("value must be a string")

        async def work(page: _Session):
            return await page.evaluate(_FILL, selector, value)
        return await self._with_page(work)

    async def click(self, selector) -> dict:
        _check_selector(selector)

        async def work(page: _Session):
            point = await page.evaluate(_CENTER, selector)
            base = {"x": point["x"], "y": point["y"], "button": "left"}
            await page.call("Input.dispatchMouseEvent", {**base, "type": "mouseMoved"})
            await page.call("Input.dispatchMouseEvent",
                            {**base, "type": "mousePressed", "clickCount": 1})
            await page.call("Input.dispatchMouseEvent",
                            {**base, "type": "mouseReleased", "clickCount": 1})
            return {"clicked": selector}
        return await self._with_page(work)

    async def tree(self) -> str:
        """The page's accessibility tree, one node per line."""
        async def work(page: _Session):
            await page.call("Accessibility.enable")
            nodes = (await page.call("Accessibility.getFullAXTree"))["nodes"]
            header = (await page.evaluate("() => document.title"),
                      await page.evaluate("() => location.href"))
            return header, nodes
        (title, url), nodes = await self._with_page(work)
        return render_tree(title, url, nodes)


def _check_selector(selector, required: bool = True) -> None:
    if selector is None and not required:
        return
    if not isinstance(selector, str) or not selector.strip():
        raise ToolError("selector must be a non-empty CSS selector string")


def render_tree(title: str, url: str, nodes: list[dict]) -> str:
    by_id = {n["nodeId"]: n for n in nodes}
    lines = [f"# {_clip(title)} - {_clip(url)}"]
    used = len(lines[0]) + 1
    stop = [False]
    skipped_roles = {"InlineTextBox", "none", "generic", "presentation"}

    def value(field):
        return (field or {}).get("value", "")

    def walk(node_id: str, depth: int, parent_name: str) -> None:
        node = by_id.get(node_id)
        if node is None or stop[0]:
            return
        role, name = str(value(node.get("role"))), str(value(node.get("name")))
        show = (not node.get("ignored") and role not in skipped_roles
                and not (role == "StaticText" and name in parent_name))
        if show:
            line = "  " * depth + role
            if name:
                line += " " + json.dumps(_clip(name))
            extra = value(node.get("value"))
            if extra != "":
                line += " value=" + json.dumps(_clip(str(extra)))
            nonlocal used
            if len(lines) > MAX_TREE_LINES or used + len(line) + 1 > MAX_TREE_BYTES:
                stop[0] = True
                return
            lines.append(line)
            used += len(line.encode("utf-8")) + 1
        for child in node.get("childIds", []):
            walk(child, depth + 1 if show else depth, name or parent_name)

    if nodes:
        walk(nodes[0]["nodeId"], 0, "")
    if stop[0]:
        lines.append(f"[... tree cut at {MAX_TREE_LINES} lines / {MAX_TREE_BYTES} bytes ...]")
    return "\n".join(lines)


def _clip(text: str) -> str:
    if len(text) <= MAX_TREE_FIELD:
        return text
    return text[:MAX_TREE_FIELD] + "..."
