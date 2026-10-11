"""Jobs: commands the agent starts through `shell` and `files run`.

A job is a child of the API that runs as the same unprivileged user, in its
own session so the whole tree can be killed, with an environment built here
from constants and the workspace - never from the API's own environment, which
holds the bearer.
"""

import asyncio
import os
import re
import signal
from dataclasses import dataclass

from .errors import ToolError

TOKEN_VAR = "LOOM_COMPUTER_TOKEN"
DEFAULT_TIMEOUT = 120.0
MAX_TIMEOUT = 3600.0
HEAD_BYTES = 96 * 1024  # of each stream: the start...
TAIL_BYTES = 96 * 1024  # ...and the end are kept; the middle is counted
EXIT_GRACE = 1.0  # pipes may stay open this long after the command exits
TERM_GRACE = 2.0
ENV_FILE = ".loom/env"  # KEY=VALUE lines the workspace hands every job

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def base_env(display: str) -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/home/agent",
        "USER": "agent",
        "LOGNAME": "agent",
        "SHELL": "/bin/bash",
        "LANG": "C.UTF-8",
        "TERM": "xterm-256color",
        "DISPLAY": display,
    }


def workspace_env(workspace: str) -> dict[str, str]:
    """Variables from `<workspace>/.loom/env`: `KEY=VALUE` lines, `#` comments,
    an optional `export `, values optionally in matching quotes. The bearer is
    never taken from here, nor is anything of the computer's own."""
    found: dict[str, str] = {}
    try:
        with open(os.path.join(workspace, ENV_FILE), encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return found
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ").lstrip()
        name, sep, value = line.partition("=")
        name = name.strip()
        if not sep or not _NAME.match(name) or name.startswith("LOOM_COMPUTER"):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        found[name] = value
    return found


def clamp_timeout(value) -> float:
    if value is None:
        return DEFAULT_TIMEOUT
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ToolError("timeout must be a positive number of seconds")
    return min(float(value), MAX_TIMEOUT)


@dataclass
class JobResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    duration: float

    def as_dict(self) -> dict:
        return {
            "exit_code": self.exit_code, "stdout": self.stdout,
            "stderr": self.stderr, "timed_out": self.timed_out,
            "truncated": self.truncated, "duration_s": round(self.duration, 3),
        }


class _Capture:
    """Reads a stream to EOF keeping its head and tail, so a chatty job can
    neither fill memory nor block on a full pipe."""

    def __init__(self):
        self.head = bytearray()
        self.tail = bytearray()
        self.total = 0

    async def drain(self, stream) -> None:
        while chunk := await stream.read(65536):
            self.total += len(chunk)
            room = HEAD_BYTES - len(self.head)
            if room > 0:
                self.head += chunk[:room]
                chunk = chunk[room:]
            if chunk:
                self.tail += chunk
                if len(self.tail) > 2 * TAIL_BYTES:
                    del self.tail[:-TAIL_BYTES]

    def text(self) -> tuple[str, bool]:
        tail = bytes(self.tail[-TAIL_BYTES:])
        omitted = self.total - len(self.head) - len(tail)
        body = bytes(self.head)
        if omitted > 0:
            body += f"\n[... {omitted} bytes omitted ...]\n".encode() + tail
        else:
            body += tail
        return body.decode("utf-8", errors="replace"), omitted > 0


class Jobs:
    def __init__(self):
        self._live: set[int] = set()  # process group ids

    async def run(self, argv: list[str], cwd: str, env: dict[str, str],
                  timeout: float) -> JobResult:
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, cwd=cwd, env=env, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                start_new_session=True)
        except FileNotFoundError:
            raise ToolError(f"cannot run {argv[0]!r}: no such file or command") from None
        except PermissionError:
            raise ToolError(f"cannot run {argv[0]!r}: permission denied") from None
        except NotADirectoryError:
            raise ToolError("cwd is not a directory") from None
        except OSError as exc:
            raise ToolError(f"cannot start the command: {exc.strerror}") from None
        group = proc.pid  # start_new_session: the child leads its own group
        self._live.add(group)
        out, err = _Capture(), _Capture()
        readers = [asyncio.ensure_future(out.drain(proc.stdout)),
                   asyncio.ensure_future(err.drain(proc.stderr))]
        timed_out = False
        try:
            try:
                await asyncio.wait_for(proc.wait(), timeout)
            except asyncio.TimeoutError:
                timed_out = True
                _signal_group(group, signal.SIGTERM)
                try:
                    await asyncio.wait_for(proc.wait(), TERM_GRACE)
                except asyncio.TimeoutError:
                    pass
            # Whatever is still in the group is the job's leftovers.
            _signal_group(group, signal.SIGKILL)
            await proc.wait()
            await asyncio.wait(readers, timeout=EXIT_GRACE)
        finally:
            _signal_group(group, signal.SIGKILL)  # also on cancellation
            self._live.discard(group)
            for reader in readers:
                reader.cancel()
        stdout, cut_out = out.text()
        stderr, cut_err = err.text()
        return JobResult(None if timed_out else proc.returncode, stdout, stderr,
                         timed_out, cut_out or cut_err, loop.time() - started)

    def kill_all(self) -> None:
        for group in list(self._live):
            _signal_group(group, signal.SIGKILL)


def _signal_group(group: int, signum: int) -> None:
    if group <= 1:
        return
    try:
        os.killpg(group, signum)
    except (ProcessLookupError, PermissionError):
        pass
