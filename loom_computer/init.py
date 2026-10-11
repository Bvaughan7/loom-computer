"""PID 1 of the image: keeps the desktop and the API up, and keeps the token
away from both the desktop and anything the agent runs.

Everything in the container shares one UID (`--cap-drop=ALL` leaves no way to
switch users), so a process that holds the bearer must be unreadable to its
siblings. Marking it non-dumpable does that: `/proc/<pid>/environ`, `mem`
and ptrace then need privileges the agent user lacks. The flag is reset by
`exec`, so this process holds the token, never execs, and runs the API as a
plain fork of itself. The desktop (supervisord) is exec'd with the token
removed from its environment.
"""

import ctypes
import os
import signal
import subprocess
import sys
import time

CONF = os.path.join(os.path.dirname(__file__), "..", "image", "supervisord.conf")
TOKEN_VAR = "LOOM_COMPUTER_TOKEN"
PR_SET_DUMPABLE = 4


def make_unreadable() -> None:
    if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        sys.exit("loom-computer: cannot mark the process non-dumpable")


def _fork_api() -> int:
    pid = os.fork()
    if pid == 0:
        try:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            from .app import main

            main()
            os._exit(0)
        except SystemExit as exit_:
            os._exit(exit_.code if isinstance(exit_.code, int) else 1)
        except BaseException:  # noqa: BLE001
            os._exit(1)
    return pid


def _signal(pid: int, signum: int) -> None:
    if pid <= 0:  # never kill(0): that is our whole process group
        return
    try:
        os.kill(pid, signum)
    except ProcessLookupError:
        pass


def run() -> int:
    make_unreadable()
    if not os.environ.get(TOKEN_VAR):
        sys.exit(f"loom-computer: {TOKEN_VAR} is not set; refusing to start "
                 "(every /mcp call needs a bearer token)")
    desktop_env = {k: v for k, v in os.environ.items() if k != TOKEN_VAR}
    desktop = subprocess.Popen(["supervisord", "-n", "-c", CONF], env=desktop_env).pid
    api = _fork_api()
    exiting: int | None = None  # set once the desktop is gone or we were told to stop

    def stop(_signum, _frame):
        nonlocal exiting
        exiting = 0 if exiting is None else exiting
        _signal(desktop, signal.SIGTERM)
        _signal(api, signal.SIGTERM)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    started = time.monotonic()
    while True:
        try:
            pid, status = os.waitpid(-1, 0)  # also reaps orphans reparented to us
        except ChildProcessError:
            return exiting or 0
        if pid == desktop:
            if exiting is None:
                exiting = os.waitstatus_to_exitcode(status) or 1
            _signal(api, signal.SIGTERM)
            desktop = 0
        elif pid == api:
            if exiting is not None:
                return exiting
            # A crashed API comes back, but not in a tight loop.
            time.sleep(max(0.0, 1.0 - (time.monotonic() - started)))
            started = time.monotonic()
            api = _fork_api()


if __name__ == "__main__":
    sys.exit(run())
