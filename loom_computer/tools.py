"""The MCP tool surface: `state`, `shell`, `files`, `browser`, `capture`.

A tool answers with an MCP result: content blocks, and `isError` when the
agent should read the text as a refusal or a failure. A command that ran and
exited non-zero is a result, not an error: the exit code is in it.
"""

import asyncio
import base64
import json
import logging
import os
import re
import stat

from .browser import Browser
from .desktop import Desktop
from .errors import ToolError
from .jobs import Jobs, base_env, clamp_timeout, workspace_env
from .workspace import Workspace

log = logging.getLogger("loom_computer")

MAX_IMAGE_EDGE = 1568
CAPTURE_MODES = ("image", "png", "tree")
INTERPRETERS = {".py": "python3", ".sh": "bash"}


def _schema(properties: dict, required: tuple = ()) -> dict:
    return {"type": "object", "properties": properties,
            "required": list(required), "additionalProperties": False}


_TIMEOUT = {"type": "number", "description":
            "Seconds before the command is killed (default 120, at most 3600)."}
_CWD = {"type": "string", "description":
        "Working directory, absolute or relative to the workspace "
        "(default /home/agent/workspace)."}

DEFINITIONS = [
    {"name": "state",
     "description": "Computer state. Action `guide` answers this release's "
                    "skill, version and checksum.",
     "inputSchema": _schema({"action": {"type": "string", "enum": ["guide"]}},
                            ("action",))},
    {"name": "shell",
     "description": "Run a command as the agent user and wait for it. Give "
                    "`command` (a string run by `bash -c`) or `argv` (a list "
                    "run directly, no shell). Answers exit_code, stdout, "
                    "stderr, timed_out.",
     "inputSchema": _schema({
         "command": {"type": "string", "description": "Shell command line."},
         "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1,
                  "description": "Program and arguments, run without a shell."},
         "cwd": _CWD, "timeout": _TIMEOUT})},
    {"name": "files",
     "description": "Files inside the workspace. Actions: read, write, list, "
                    "run (execute a script file as a job, like shell).",
     "inputSchema": _schema({
         "action": {"type": "string", "enum": ["read", "write", "list", "run"]},
         "path": {"type": "string", "description":
                  "Path inside the workspace (relative or absolute). "
                  "Default `.` for list."},
         "content": {"type": "string", "description": "write: the data."},
         "encoding": {"type": "string", "enum": ["utf-8", "base64"],
                      "description": "read/write: how content is carried "
                                     "(default utf-8)."},
         "append": {"type": "boolean", "description": "write: append instead of replace."},
         "args": {"type": "array", "items": {"type": "string"},
                  "description": "run: arguments for the script."},
         "cwd": _CWD, "timeout": _TIMEOUT}, ("action",))},
    {"name": "browser",
     "description": "Drive the desktop's Chromium (the active tab). Actions: "
                    "navigate (url), title, text (optional selector), fill "
                    "(selector, value), click (selector).",
     "inputSchema": _schema({
         "action": {"type": "string",
                    "enum": ["navigate", "title", "text", "fill", "click"]},
         "url": {"type": "string"},
         "selector": {"type": "string", "description": "CSS selector."},
         "value": {"type": "string", "description": "fill: the text to enter."}},
         ("action",))},
    {"name": "capture",
     "description": "Look at the computer. mode `image`: screenshot scaled to "
                    "at most 1568 px on the longer edge; `png`: unscaled; "
                    "`tree`: the browser page's accessibility tree as text. "
                    "`window` (1-based index or part of a title) and `region` "
                    "[x, y, w, h] (within the window, else the screen) narrow "
                    "image and png.",
     "inputSchema": _schema({
         "mode": {"type": "string", "enum": list(CAPTURE_MODES)},
         "window": {"type": "string"},
         "region": {"type": "array", "items": {"type": "integer"},
                    "minItems": 4, "maxItems": 4}}, ("mode",))},
]


def text_result(body, error: bool = False) -> dict:
    """A text block; a dict body also rides as structuredContent."""
    if isinstance(body, str):
        return {"content": [{"type": "text", "text": body}], "isError": error}
    return {"content": [{"type": "text", "text": json.dumps(body)}],
            "structuredContent": body, "isError": error}


def _error(message: str) -> dict:
    return text_result(message, error=True)


def _printable(value: str, limit: int = 64) -> str:
    return re.sub(r"[^\x20-\x7e]", "?", value)[:limit]


def _pick(args: dict, allowed: tuple) -> None:
    extra = sorted(set(args) - set(allowed))
    if extra:
        raise ToolError("unknown argument " + _printable(extra[0]))


class Tools:
    def __init__(self, guide, desktop: Desktop, workspace: str,
                 browser: Browser | None = None):
        self._guide = guide
        self._desktop = desktop
        self.workspace = Workspace(workspace)
        self.browser = browser or Browser()
        self.jobs = Jobs()

    def has(self, name: str) -> bool:
        return any(d["name"] == name for d in DEFINITIONS)

    def shutdown(self) -> None:
        self.jobs.kill_all()

    async def call(self, name: str, args: dict) -> dict:
        handler = getattr(self, f"_{name}")
        try:
            return await handler(args)
        except ToolError as exc:
            return _error(f"{name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - a tool bug is an answer, not a 500
            log.exception("tool %s failed", name)
            return _error(f"{name}: unexpected {type(exc).__name__}; the call was not completed")

    # -- state ----------------------------------------------------------------

    async def _state(self, args: dict) -> dict:
        action = args.get("action")
        if action == "guide":
            return text_result(self._guide())
        shown = _printable(action) if isinstance(action, str) else ""
        return _error(f"state: unknown action {shown}")

    # -- jobs -----------------------------------------------------------------

    def _job_env(self) -> dict[str, str]:
        env = base_env(self._desktop.display)
        env.update(workspace_env(self.workspace.root))
        return env

    def _cwd(self, value) -> str:
        if value is None:
            return self.workspace.root
        if not isinstance(value, str) or not value or "\0" in value:
            raise ToolError("cwd must be a non-empty string")
        path = value if os.path.isabs(value) else os.path.join(self.workspace.root, value)
        if not os.path.isdir(path):
            raise ToolError("cwd is not a directory")
        return os.path.realpath(path)

    async def _run_job(self, argv: list[str], args: dict,
                       pass_fds: tuple[int, ...] = ()) -> dict:
        timeout = clamp_timeout(args.get("timeout"))
        result = await self.jobs.run(argv, self._cwd(args.get("cwd")),
                                     self._job_env(), timeout, pass_fds)
        return text_result(result.as_dict())

    async def _shell(self, args: dict) -> dict:
        _pick(args, ("command", "argv", "cwd", "timeout"))
        command, argv = args.get("command"), args.get("argv")
        if (command is None) == (argv is None):
            raise ToolError("give exactly one of `command` (shell string) or `argv` (list)")
        if command is not None:
            if not isinstance(command, str) or not command.strip():
                raise ToolError("command must be a non-empty string")
            argv = ["/bin/bash", "-c", command]
        elif (not isinstance(argv, list) or not argv
              or not all(isinstance(a, str) for a in argv) or not argv[0]):
            raise ToolError("argv must be a non-empty list of strings")
        return await self._run_job(argv, args)

    # -- files ----------------------------------------------------------------

    async def _files(self, args: dict) -> dict:
        _pick(args, ("action", "path", "content", "encoding", "append", "args",
                     "cwd", "timeout"))
        action, path = args.get("action"), args.get("path")
        encoding = args.get("encoding", "utf-8")
        if encoding not in ("utf-8", "base64"):
            raise ToolError('encoding must be "utf-8" or "base64"')
        if action == "read":
            return text_result(await _blocking(self.workspace.read, path, encoding))
        if action == "write":
            append = args.get("append", False)
            if not isinstance(append, bool):
                raise ToolError("append must be a boolean")
            return text_result(await _blocking(
                self.workspace.write, path, args.get("content"), encoding, append))
        if action == "list":
            return text_result(await _blocking(self.workspace.list, path or "."))
        if action == "run":
            return await self._files_run(path, args)
        shown = _printable(action) if isinstance(action, str) else ""
        raise ToolError(f"unknown action {shown} (one of: read, write, list, run)")

    async def _files_run(self, path, args: dict) -> dict:
        # The script is opened once, without following links, and run from
        # that descriptor: the file that was checked is the file that runs.
        fd, _, rel = await _blocking(self.workspace.open_regular, path)
        try:
            script_args = args.get("args", [])
            if not isinstance(script_args, list) or not all(isinstance(a, str) for a in script_args):
                raise ToolError("args must be a list of strings")
            via = f"/dev/fd/{fd}"
            interpreter = INTERPRETERS.get(os.path.splitext(rel)[1].lower())
            if interpreter is not None:
                argv = [interpreter, via, *script_args]
            elif os.fstat(fd).st_mode & stat.S_IXUSR:
                argv = [via, *script_args]
            else:
                raise ToolError("file is not executable and has no known script "
                                "extension (.py, .sh); chmod +x it or use shell")
            return await self._run_job(argv, args, (fd,))
        finally:
            os.close(fd)

    # -- browser --------------------------------------------------------------

    async def _browser(self, args: dict) -> dict:
        _pick(args, ("action", "url", "selector", "value"))
        action, b = args.get("action"), self.browser
        if action == "navigate":
            return text_result(await b.navigate(args.get("url")))
        if action == "title":
            return text_result(await b.title())
        if action == "text":
            return text_result(await b.text(args.get("selector")))
        if action == "fill":
            return text_result(await b.fill(args.get("selector"), args.get("value")))
        if action == "click":
            return text_result(await b.click(args.get("selector")))
        shown = _printable(action) if isinstance(action, str) else ""
        raise ToolError(f"unknown action {shown} "
                        "(one of: navigate, title, text, fill, click)")

    # -- capture --------------------------------------------------------------

    async def _capture(self, args: dict) -> dict:
        _pick(args, ("mode", "window", "region"))
        mode, window, region = args.get("mode"), args.get("window"), args.get("region")
        if mode not in CAPTURE_MODES:
            shown = _printable(mode) if isinstance(mode, str) else ""
            raise ToolError(f'unknown action "{shown}" (one of: ["tree", "png", "image"])')
        if window is not None and not isinstance(window, str):
            raise ToolError("window must be a string")
        if region is not None:
            if (not isinstance(region, list) or len(region) != 4
                    or not all(isinstance(v, int) and not isinstance(v, bool) for v in region)
                    or region[2] <= 0 or region[3] <= 0):
                raise ToolError("region must be [x, y, width, height] integers, "
                                "width and height positive")
        if mode == "tree":
            if window is not None or region is not None:
                raise ToolError("window and region apply to image and png only")
            return text_result(await self.browser.tree())
        try:
            png, source, out = await self._desktop.capture(
                window, region, MAX_IMAGE_EDGE if mode == "image" else None)
        except ToolError:
            raise
        except Exception:  # noqa: BLE001
            raise ToolError("the desktop is not available") from None
        note = f"{out[0]}x{out[1]} image"
        if out != source:
            note += f"; scaled from {source[0]}x{source[1]}, 1 px = {source[0] / out[0]:.2f} screen px"
        else:
            note += "; 1 px = 1 screen px"
        return {"content": [
            {"type": "image", "data": base64.b64encode(png).decode("ascii"),
             "mimeType": "image/png"},
            {"type": "text", "text": note}], "isError": False}


async def _blocking(fn, *args):
    return await asyncio.to_thread(fn, *args)
