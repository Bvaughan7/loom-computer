"""End to end against a real X server: pixels on the screen arrive as a JPEG
frame over /ws, and injected input moves the pointer. Needs `Xvfb`."""

import io
import json
import os
import shutil
import subprocess
import time

import pytest
from fastapi.testclient import TestClient

from loom_computer.app import create_app
from loom_computer.desktop import Desktop

pytestmark = pytest.mark.skipif(shutil.which("Xvfb") is None, reason="Xvfb not installed")

TOKEN = "smoke-token"


def paint(display_name, rgb):
    """Cover the screen with one colour (a window, as `xsetroot` does not
    reliably repaint under Xvfb)."""
    from Xlib import X, display as xdisplay

    d = xdisplay.Display(display_name)
    screen = d.screen()
    pixel = screen.default_colormap.alloc_color(*(c * 257 for c in rgb)).pixel
    window = screen.root.create_window(
        0, 0, screen.width_in_pixels, screen.height_in_pixels, 0, screen.root_depth,
        X.InputOutput, X.CopyFromParent, background_pixel=pixel, override_redirect=True)
    window.map()
    d.sync()
    return d  # keep the connection open: the window lives as long as it


@pytest.fixture
def display():
    number = 90 + os.getpid() % 500
    name = f":{number}"
    proc = subprocess.Popen(
        ["Xvfb", name, "-screen", "0", "800x600x24", "-nolisten", "tcp"],
        stderr=subprocess.DEVNULL)
    socket = f"/tmp/.X11-unix/X{number}"
    for _ in range(100):
        if os.path.exists(socket):
            break
        time.sleep(0.05)
    else:
        proc.kill()
        pytest.skip("Xvfb did not come up")
    yield name
    proc.terminate()
    proc.wait(5)


def test_frame_flows_end_to_end(display):
    from PIL import Image

    painter = paint(display, (255, 0, 0))
    client = TestClient(create_app(TOKEN, desktop=Desktop(display)))
    with client.websocket_connect(f"/ws?token={TOKEN}") as ws:
        assert ws.receive_json() == {"type": "hello", "width": 800, "height": 600}
        frame = ws.receive_bytes()
        assert frame[:2] == b"\xff\xd8"  # JPEG
        image = Image.open(io.BytesIO(frame)).convert("RGB")
        assert image.size == (800, 600)
        r, g, b = image.getpixel((400, 300))
        assert r > 200 and g < 60 and b < 60

        # A change on screen produces a new frame.
        painter.close()
        painter = paint(display, (0, 0, 255))
        for _ in range(20):
            image = Image.open(io.BytesIO(ws.receive_bytes())).convert("RGB")
            if image.getpixel((400, 300))[2] > 200:
                break
        else:
            pytest.fail("no frame showed the new colour")
        painter.close()


def test_pointer_input_reaches_x(display):
    from Xlib import display as xdisplay

    client = TestClient(create_app(TOKEN, desktop=Desktop(display)))
    with client.websocket_connect(f"/ws?token={TOKEN}") as ws:
        ws.receive_json(), ws.receive_bytes()
        ws.send_text(json.dumps({"t": "pointer", "x": 123, "y": 234, "buttons": 0}))
        probe = xdisplay.Display(display)
        for _ in range(40):
            pos = probe.screen().root.query_pointer()
            if (pos.root_x, pos.root_y) == (123, 234):
                break
            time.sleep(0.05)
        else:
            pytest.fail(f"pointer at {pos.root_x},{pos.root_y}")
        probe.close()
