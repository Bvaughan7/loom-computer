"""Built-image smoke test. Set LOOM_TEST_IMAGE=<tag> to run it (needs docker):

    docker build -t loom-computer:test . && LOOM_TEST_IMAGE=loom-computer:test pytest tests/test_image.py
"""

import asyncio
import io
import os
import socket
import subprocess
import time
import urllib.request

import pytest

IMAGE = os.environ.get("LOOM_TEST_IMAGE")
pytestmark = pytest.mark.skipif(not IMAGE, reason="LOOM_TEST_IMAGE not set")
TOKEN = "image-smoke-token"


def docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


@pytest.fixture(scope="module")
def container():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    name = f"loom-computer-test-{os.getpid()}"
    docker("run", "-d", "--name", name, "--cap-drop=ALL",
           "--security-opt", "no-new-privileges", "--shm-size=256m",
           "--pids-limit=512", "-m", "2g", "-p", f"127.0.0.1:{port}:8787",
           "-e", f"LOOM_COMPUTER_TOKEN={TOKEN}", IMAGE)
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        else:
            pytest.fail("container never became healthy:\n" + docker("logs", name).stdout)
        yield name, port
    finally:
        docker("rm", "-f", name, check=False)


def test_nothing_runs_as_root(container):
    name, _ = container
    users = docker("exec", name, "ps", "-eo", "user=").stdout.split()
    assert users and set(users) == {"agent"}


def test_desktop_processes_are_up_without_the_token(container):
    name, _ = container
    for proc in ("Xvfb", "openbox", "chromium"):
        deadline = time.time() + 30
        while docker("exec", name, "pgrep", "-x", proc, check=False).returncode:
            assert time.time() < deadline, f"{proc} is not running"
            time.sleep(0.5)
    leaked = docker("exec", name, "sh", "-c",
                    "for p in $(pgrep -x Xvfb; pgrep -x openbox; pgrep -x chromium); do "
                    "tr '\\0' '\\n' < /proc/$p/environ; done | grep -c LOOM_COMPUTER_TOKEN",
                    check=False).stdout.strip()
    assert leaked == "0"


def test_screenshot_equivalent_over_ws(container):
    import websockets
    from PIL import Image

    _, port = container

    async def first_frame():
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws?token={TOKEN}") as ws:
            hello = await ws.recv()
            return hello, await ws.recv()

    hello, frame = asyncio.run(first_frame())
    assert '"width": 1280' in hello and '"height": 800' in hello
    image = Image.open(io.BytesIO(frame))
    assert image.size == (1280, 800)
    assert len(set(image.convert("L").resize((64, 40)).getdata())) > 3  # not a blank screen


def test_missing_token_refuses_to_start():
    r = docker("run", "--rm", IMAGE, check=False)
    assert r.returncode != 0 and "LOOM_COMPUTER_TOKEN" in r.stderr
