"""Input shared between viewers (fake X, no server needed)."""

import asyncio

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
