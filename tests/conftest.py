import os
import subprocess
import time

import pytest


def start_xvfb(width: int, height: int, offset: int = 0):
    number = 90 + (os.getpid() + offset) % 500
    name = f":{number}"
    proc = subprocess.Popen(
        ["Xvfb", name, "-screen", "0", f"{width}x{height}x24", "-nolisten", "tcp"],
        stderr=subprocess.DEVNULL)
    socket = f"/tmp/.X11-unix/X{number}"
    for _ in range(100):
        if os.path.exists(socket):
            return name, proc
        time.sleep(0.05)
    proc.kill()
    pytest.skip("Xvfb did not come up")


@pytest.fixture
def display():
    name, proc = start_xvfb(800, 600)
    yield name
    proc.terminate()
    proc.wait(5)


@pytest.fixture
def big_display():
    """A screen wider than the 1568 px a screenshot is scaled to."""
    name, proc = start_xvfb(2400, 1200, offset=1)
    yield name
    proc.terminate()
    proc.wait(5)
