"""File operations confined to the workspace root."""

import base64
import errno
import os
import stat

from .errors import ToolError

MAX_READ = 1024 * 1024
MAX_WRITE = 8 * 1024 * 1024
MAX_ENTRIES = 1000


class Workspace:
    def __init__(self, root: str):
        self.root = os.path.realpath(root)

    def resolve(self, path) -> str:
        """The real path of `path` (relative to the root, or absolute inside
        it). Symlinks are followed before the check, so a link out of the
        workspace is refused like `..` is."""
        if not isinstance(path, str) or not path or "\0" in path:
            raise ToolError("path must be a non-empty string")
        try:
            path.encode("utf-8")
        except UnicodeEncodeError:
            raise ToolError("path is not valid Unicode text") from None
        joined = path if os.path.isabs(path) else os.path.join(self.root, path)
        real = os.path.realpath(joined)
        if real != self.root and not real.startswith(self.root + os.sep):
            raise ToolError(f"path is outside the workspace ({self.root})")
        return real

    def relative(self, real: str) -> str:
        return os.path.relpath(real, self.root)

    def _open(self, real: str, flags: int, mode: int = 0o666,
              make_dirs: bool = False) -> int:
        """Open `real` (a path `resolve` returned) without trusting any name.

        The walk starts at the root and takes each component with
        O_NOFOLLOW relative to the directory fd already held, so a directory
        swapped for a symlink after `resolve` is refused instead of followed:
        the path that was checked is the object that is used.
        """
        parts = [p for p in os.path.relpath(real, self.root).split(os.sep) if p != "."]
        if not parts:
            raise ToolError("path is a directory")
        try:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ToolError(f"cannot open workspace: {exc.strerror}") from None
        try:
            for part in parts[:-1]:
                if make_dirs:
                    try:
                        os.mkdir(part, 0o777, dir_fd=fd)
                    except FileExistsError:
                        pass
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = nxt
            return os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_NONBLOCK,
                           mode, dir_fd=fd)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise ToolError("path changed while it was being opened "
                                "(a symlink is not followed)") from None
            if exc.errno == errno.ENOENT:
                raise ToolError("no such file") from None
            raise ToolError(f"cannot open: {exc.strerror}") from None
        finally:
            os.close(fd)

    def open_regular(self, path) -> tuple[int, int, str]:
        """(fd, size, workspace-relative path) of a regular file to read.
        The caller closes the fd."""
        real = self.resolve(path)
        fd = self._open(real, os.O_RDONLY)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ToolError("not a regular file (use action list for directories)")
        except BaseException:
            os.close(fd)
            raise
        return fd, info.st_size, self.relative(real)

    def read(self, path, encoding: str = "utf-8") -> dict:
        fd, size, rel = self.open_regular(path)
        with os.fdopen(fd, "rb") as handle:
            if size > MAX_READ:
                raise ToolError(f"file is {size} bytes; reads are limited to {MAX_READ}")
            data = handle.read(MAX_READ + 1)
        if encoding == "base64":
            content = base64.b64encode(data).decode("ascii")
        else:
            try:
                content = data.decode("utf-8")
            except UnicodeDecodeError:
                raise ToolError('file is not UTF-8 text; read it with encoding "base64"') from None
        return {"path": rel, "bytes": len(data),
                "encoding": encoding, "content": content}

    def write(self, path, content, encoding: str = "utf-8", append: bool = False) -> dict:
        if not isinstance(content, str):
            raise ToolError("content must be a string")
        if encoding == "base64":
            try:
                data = base64.b64decode(content, validate=True)
            except ValueError:
                raise ToolError("content is not valid base64") from None
        else:
            try:
                data = content.encode("utf-8")
            except UnicodeEncodeError:
                raise ToolError("content is not valid Unicode text (it holds a lone "
                                "surrogate); send binary data with encoding base64") from None
        if len(data) > MAX_WRITE:
            raise ToolError(f"writes are limited to {MAX_WRITE} bytes")
        real = self.resolve(path)
        if real == self.root or os.path.isdir(real):
            raise ToolError("path is a directory")
        flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else 0)
        fd = self._open(real, flags, make_dirs=True)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ToolError("not a regular file")
            if not append:
                os.ftruncate(fd, 0)
            with os.fdopen(fd, "wb", closefd=False) as handle:
                handle.write(data)
        except OSError as exc:
            raise ToolError(f"cannot write: {exc.strerror}") from None
        finally:
            os.close(fd)
        return {"path": self.relative(real), "bytes": len(data), "appended": append}

    def list(self, path=".") -> dict:
        real = self.resolve(path)
        if not os.path.isdir(real):
            raise ToolError("not a directory")
        entries = []
        truncated = False
        with os.scandir(real) as scan:
            for entry in scan:
                if len(entries) >= MAX_ENTRIES:
                    truncated = True
                    break
                if entry.is_symlink():
                    kind = "symlink"
                elif entry.is_dir():
                    kind = "dir"
                elif entry.is_file():
                    kind = "file"
                else:
                    kind = "other"
                try:
                    size = entry.stat(follow_symlinks=False).st_size if kind == "file" else None
                except OSError:
                    size = None
                name = entry.name.encode("utf-8", "replace").decode("utf-8")
                entries.append({"name": name, "type": kind, "size": size})
        entries.sort(key=lambda e: e["name"])
        return {"path": self.relative(real), "entries": entries, "truncated": truncated}
