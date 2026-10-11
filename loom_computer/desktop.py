"""The desktop as the viewer sees it: frames out, input in.

Frames are JPEGs of the X root window, captured with `mss` and sent only when the screen changed. Input is injected with the XTEST
extension (`python-xlib`). Both X connections live on one worker thread: Xlib
connections are not thread-safe.
"""

import asyncio
import hashlib
import io
import logging
import os
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger("loom_computer.desktop")

FPS = 10
JPEG_QUALITY = 70

# DOM `MouseEvent.buttons` bit -> X button number.
_BUTTON_BITS = ((1, 1), (4, 2), (2, 3))
_WHEEL_UP, _WHEEL_DOWN = 4, 5

_NAMED_KEYSYMS = {
    "Backspace": 0xFF08, "Tab": 0xFF09, "Enter": 0xFF0D, "Escape": 0xFF1B,
    "Delete": 0xFFFF, "Home": 0xFF50, "ArrowLeft": 0xFF51, "ArrowUp": 0xFF52,
    "ArrowRight": 0xFF53, "ArrowDown": 0xFF54, "PageUp": 0xFF55,
    "PageDown": 0xFF56, "End": 0xFF57, "Insert": 0xFF63, "Shift": 0xFFE1,
    "Control": 0xFFE3, "CapsLock": 0xFFE5, "Meta": 0xFFE7, "Alt": 0xFFE9,
    **{f"F{n}": 0xFFBE + n - 1 for n in range(1, 13)},
}


def keysym_for(key) -> int | None:
    """X keysym for a DOM `KeyboardEvent.key` value, None when unmapped."""
    if not isinstance(key, str) or not key:
        return None
    if key in _NAMED_KEYSYMS:
        return _NAMED_KEYSYMS[key]
    if len(key) == 1:
        code = ord(key)
        return code if code < 0x100 else 0x01000000 + code
    return None


class Desktop:
    """One X display: `frame()` to look, `InputSession`s to touch."""

    def __init__(self, display: str | None = None):
        self.display = display or os.environ.get("DISPLAY", ":99")
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="x11")
        self._grabber = None
        self._xdisplay = None
        # X input state is shared by every viewer: how many sessions hold each
        # keycode / button, so one closing cannot release another's input.
        self._held_keys: dict[int, int] = {}
        self._held_buttons: dict[int, int] = {}

    # -- worker-thread side ------------------------------------------------

    def _grab(self) -> tuple[int, int, bytes]:
        import mss

        if self._grabber is None:
            self._grabber = mss.MSS(display=self.display)
        shot = self._grabber.grab(self._grabber.monitors[0])
        return shot.width, shot.height, bytes(shot.bgra)

    def _x(self):
        from Xlib import display

        if self._xdisplay is None:
            self._xdisplay = display.Display(self.display)
        return self._xdisplay

    def _fake(self, kind: str, detail: int, x: int = 0, y: int = 0) -> None:
        from Xlib import X
        from Xlib.ext import xtest

        d = self._x()
        types = {"key_down": X.KeyPress, "key_up": X.KeyRelease,
                 "btn_down": X.ButtonPress, "btn_up": X.ButtonRelease,
                 "motion": X.MotionNotify}
        if kind == "motion":
            xtest.fake_input(d, X.MotionNotify, 0, x=x, y=y)
        else:
            xtest.fake_input(d, types[kind], detail)
        d.sync()

    def _keycode(self, keysym: int) -> int:
        return self._x().keysym_to_keycode(keysym)

    def _drop(self) -> None:
        for conn in (self._grabber, self._xdisplay):
            try:
                if conn is not None:
                    conn.close()
            except Exception:  # noqa: BLE001 - the display may already be gone
                pass
        self._grabber = self._xdisplay = None

    # -- asyncio side ------------------------------------------------------

    async def _run(self, fn, *args):
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(self._pool, fn, *args)
        except Exception:
            # Reconnect on the next call (X restarted, display not up yet).
            await loop.run_in_executor(self._pool, self._drop)
            raise

    async def frame(self) -> tuple[int, int, bytes, bytes]:
        """(width, height, JPEG, digest of the raw pixels)."""
        width, height, bgra = await self._run(self._grab)
        digest = hashlib.blake2b(bgra, digest_size=16).digest()
        jpeg = await self._run(_encode, width, height, bgra)
        return width, height, jpeg, digest

    async def key_down(self, keysym: int) -> int | None:
        code = await self._run(self._keycode, keysym)
        if code:
            self._held_keys[code] = self._held_keys.get(code, 0) + 1
            await self._run(self._fake, "key_down", code)
            return code
        return None

    async def key_up(self, keycode: int) -> None:
        if _release(self._held_keys, keycode):
            await self._run(self._fake, "key_up", keycode)

    async def button(self, number: int, down: bool) -> None:
        if down:
            self._held_buttons[number] = self._held_buttons.get(number, 0) + 1
        elif not _release(self._held_buttons, number):
            return
        await self._run(self._fake, "btn_down" if down else "btn_up", number)

    async def move(self, x: int, y: int) -> None:
        await self._run(self._fake, "motion", 0, x, y)


def _release(held: dict[int, int], item: int) -> bool:
    """Drop one hold on `item`; True when nobody holds it any more."""
    count = held.get(item, 0) - 1
    if count > 0:
        held[item] = count
        return False
    held.pop(item, None)
    return True


def _encode(width: int, height: int, bgra: bytes) -> bytes:
    from PIL import Image

    image = Image.frombuffer("RGB", (width, height), bgra, "raw", "BGRX", 0, 1)
    out = io.BytesIO()
    image.save(out, "JPEG", quality=JPEG_QUALITY)
    return out.getvalue()


class InputSession:
    """One viewer's input. Whatever it holds down is let go when it closes."""

    def __init__(self, desktop: Desktop, width: int, height: int):
        self.desktop = desktop
        self.width, self.height = width, height
        self._buttons = 0
        self._keys: dict[str, int] = {}  # DOM key -> held X keycode

    async def handle(self, event) -> None:
        """Apply one decoded JSON event; anything malformed is ignored."""
        if not isinstance(event, dict):
            return
        kind = event.get("t")
        if kind == "pointer":
            await self._pointer(event.get("x"), event.get("y"), event.get("buttons"))
        elif kind == "wheel":
            dy = event.get("dy")
            if _is_int(dy) and dy:
                number = _WHEEL_DOWN if dy > 0 else _WHEEL_UP
                await self.desktop.button(number, True)
                await self.desktop.button(number, False)
        elif kind == "key":
            await self._key(event.get("key"), event.get("down"))

    async def _pointer(self, x, y, buttons) -> None:
        if not (_is_int(x) and _is_int(y) and _is_int(buttons)):
            return
        x = min(max(x, 0), self.width - 1)
        y = min(max(y, 0), self.height - 1)
        await self.desktop.move(x, y)
        for bit, number in _BUTTON_BITS:
            was, now = bool(self._buttons & bit), bool(buttons & bit)
            if was != now:
                await self.desktop.button(number, now)
        self._buttons = buttons & 7

    async def _key(self, key, down) -> None:
        if not isinstance(down, bool):
            return
        keysym = keysym_for(key)
        if keysym is None:
            return
        if down:
            if key in self._keys:  # auto-repeat: release first so it re-fires
                await self.desktop.key_up(self._keys[key])
            code = await self.desktop.key_down(keysym)
            if code:
                self._keys[key] = code
        elif key in self._keys:
            await self.desktop.key_up(self._keys.pop(key))

    async def release_all(self) -> None:
        try:
            for bit, number in _BUTTON_BITS:
                if self._buttons & bit:
                    await self.desktop.button(number, False)
            for code in self._keys.values():
                await self.desktop.key_up(code)
        except Exception:  # noqa: BLE001 - nothing left to release on a dead display
            log.debug("release_all failed", exc_info=True)
        self._buttons, self._keys = 0, {}


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class FrameHub:
    """One capture loop shared by every connected viewer.

    Runs only while someone is subscribed. A subscriber's queue holds the
    newest frame only, so a slow peer skips frames instead of lagging.
    """

    def __init__(self, desktop: Desktop, fps: int = FPS):
        self.desktop = desktop
        self.interval = 1.0 / fps
        self._subs: set[asyncio.Queue] = set()
        self._task: asyncio.Task | None = None
        self._last: tuple[int, int, bytes] | None = None

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=1)
        if self._last is not None:
            queue.put_nowait(self._last)
        self._subs.add(queue)
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self._run())
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subs.discard(queue)

    async def _run(self) -> None:
        digest = None
        try:
            while self._subs:
                try:
                    width, height, jpeg, new_digest = await self.desktop.frame()
                except Exception as exc:  # noqa: BLE001
                    self._publish(exc)
                    return
                if new_digest != digest:
                    digest = new_digest
                    self._last = (width, height, jpeg)
                    self._publish(self._last)
                await asyncio.sleep(self.interval)
        finally:
            self._last = None

    def _publish(self, item) -> None:
        for queue in list(self._subs):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(item)
