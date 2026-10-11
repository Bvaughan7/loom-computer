"""Input shared between viewers (fake X, no server needed)."""

import asyncio
import threading

import pytest

from loom_computer.desktop import Desktop, InputSession


def test_shared_input_is_released_only_by_its_last_holder():
    desktop = Desktop(":0")
    sent = []
    desktop._fake = lambda kind, detail, x=0, y=0: sent.append((kind, detail))
    desktop._keycode = lambda keysym: 38

    async def scenario():
        a, b = InputSession(desktop, 100, 100), InputSession(desktop, 100, 100)
        for session in (a, b):
            await session.handle({"t": "key", "key": "a", "down": True})
            await session.handle({"t": "pointer", "x": 1, "y": 1, "buttons": 1})
        sent.clear()
        await a.release_all()
        assert sent == []  # b still holds the key and the button
        await b.release_all()
        assert sorted(sent) == [("btn_up", 1), ("key_up", 38)]

    asyncio.run(scenario())


def _gated_desktop():
    """Desktop whose injections block in the executor until `gate` is set."""
    desktop = Desktop(":0")
    sent, gate = [], threading.Event()

    def fake(kind, detail, x=0, y=0):
        if kind.endswith("_down"):
            gate.wait(5)
        sent.append((kind, detail))

    desktop._fake = fake
    desktop._keycode = lambda keysym: 38
    return desktop, sent, gate


async def _settle(sent, expected):
    for _ in range(200):
        if len(sent) >= expected:
            return
        await asyncio.sleep(0.01)


def test_cancel_mid_injection_leaves_no_orphaned_hold():
    desktop, sent, gate = _gated_desktop()

    async def scenario():
        a, b = InputSession(desktop, 100, 100), InputSession(desktop, 100, 100)
        task = asyncio.ensure_future(a.handle({"t": "pointer", "x": 1, "y": 1, "buttons": 1}))
        key_task = asyncio.ensure_future(a.handle({"t": "key", "key": "a", "down": True}))
        await asyncio.sleep(0.05)  # both injections are in flight
        task.cancel()
        key_task.cancel()
        for t in (task, key_task):
            with pytest.raises(asyncio.CancelledError):
                await t
        # b shares the same button and key while a's injections are pending
        gate.set()
        await _settle(sent, 2)
        await b.handle({"t": "pointer", "x": 1, "y": 1, "buttons": 1})
        await b.handle({"t": "key", "key": "a", "down": True})
        sent.clear()
        await a.release_all()  # a's record survived the cancel
        assert sent == []  # b still holds both
        await b.release_all()
        assert sorted(sent) == [("btn_up", 1), ("key_up", 38)]
        assert desktop._held_buttons == {} and desktop._held_keys == {}

    asyncio.run(scenario())


def test_cancelled_sole_holder_still_gets_final_x_release():
    desktop, sent, gate = _gated_desktop()

    async def scenario():
        a = InputSession(desktop, 100, 100)
        task = asyncio.ensure_future(a.handle({"t": "pointer", "x": 1, "y": 1, "buttons": 1}))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        gate.set()
        await _settle(sent, 1)
        await a.release_all()  # the disconnect handler
        assert ("btn_up", 1) in sent
        assert desktop._held_buttons == {}

    asyncio.run(scenario())
