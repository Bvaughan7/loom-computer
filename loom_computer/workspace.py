"""File operations confined to the workspace root."""

import base64
import os

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
        joined = path if os.path.isabs(path) else os.path.join(self.root, path)
        real = os.path.realpath(joined)
        if real != self.root and not real.startswith(self.root + os.sep):
            raise ToolError(f"path is outside the workspace ({self.root})")
        return real

    def relative(self, real: str) -> str:
        return os.path.relpath(real, self.root)

    def read(self, path, encoding: str = "utf-8") -> dict:
        real = self.resolve(path)
        if not os.path.exists(real):
            raise ToolError("no such file")
        if not os.path.isfile(real):
            raise ToolError("not a regular file (use action list for directories)")
        size = os.path.getsize(real)
        if size > MAX_READ:
            raise ToolError(f"file is {size} bytes; reads are limited to {MAX_READ}")
        with open(real, "rb") as handle:
            data = handle.read(MAX_READ + 1)
        if encoding == "base64":
            content = base64.b64encode(data).decode("ascii")
        else:
            try:
                content = data.decode("utf-8")
            except UnicodeDecodeError:
                raise ToolError('file is not UTF-8 text; read it with encoding "base64"') from None
        return {"path": self.relative(real), "bytes": len(data),
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
            data = content.encode("utf-8")
        if len(data) > MAX_WRITE:
            raise ToolError(f"writes are limited to {MAX_WRITE} bytes")
        real = self.resolve(path)
        if real == self.root or os.path.isdir(real):
            raise ToolError("path is a directory")
        try:
            os.makedirs(os.path.dirname(real), exist_ok=True)
            with open(real, "ab" if append else "wb") as handle:
                handle.write(data)
        except OSError as exc:
            raise ToolError(f"cannot write: {exc.strerror}") from None
        return {"path": self.relative(real), "bytes": len(data), "appended": append}

    def list(self, path=".") -> dict:
        real = self.resolve(path)
        if not os.path.isdir(real):
            raise ToolError("not a directory")
        entries = []
        with os.scandir(real) as scan:
            for entry in sorted(scan, key=lambda e: e.name):
                if len(entries) >= MAX_ENTRIES:
                    break
                if entry.is_symlink():
                    kind = "symlink"
                elif entry.is_dir():
                    kind = "dir"
                elif entry.is_file():
                    kind = "file"
                else:
                    kind = "other"
                size = entry.stat(follow_symlinks=False).st_size if kind == "file" else None
                entries.append({"name": entry.name, "type": kind, "size": size})
        return {"path": self.relative(real), "entries": entries,
                "truncated": len(entries) >= MAX_ENTRIES}
