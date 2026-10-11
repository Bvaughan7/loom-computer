"""The granted secret set: this store holds it in memory only and never
answers it back.

`PUT /secrets` replaces the whole set. Nothing here writes to disk, logs a
value, or echoes one in an error: a refusal names the secret and the shape
that was wrong, never what it held. (What a job does with its own environment,
and what the browser profile keeps, is outside this store.)
"""

import base64
import binascii
import hmac
import json
import logging
import re
import struct
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import ToolError

REDACTED = "[REDACTED]"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_HOST = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?\Z")


class SecretsError(ValueError):
    """A set that cannot be taken. The message never holds a secret value."""


@dataclass(frozen=True)
class Login:
    name: str
    sites: tuple[str, ...]
    username: str
    password: str
    totp: str | None = None

    def totp_code(self, now: float | None = None) -> str:
        if not self.totp:
            raise ToolError("this login has no totp secret")
        return totp_code(self.totp, time.time() if now is None else now)


def totp_lifetime(now: float, step: int = 30, margin: int = 10) -> float:
    """Seconds a code made at `now` should stay masked: the rest of its step
    and a margin for a site that is slow to echo it."""
    return step - (now % step) + margin


def totp_code(secret: str, now: float, digits: int = 6, step: int = 30) -> str:
    """RFC 6238, SHA-1. `secret` is base32 (spaces and case ignored) or an
    otpauth:// URI carrying one."""
    if secret.lower().startswith("otpauth://"):
        match = re.search(r"[?&]secret=([^&]+)", secret, re.I)
        secret = match.group(1) if match else ""
    text = re.sub(r"[\s-]", "", secret).upper()
    try:
        key = base64.b32decode(text + "=" * (-len(text) % 8))
    except (binascii.Error, ValueError):
        raise ToolError("the totp secret is not valid base32") from None
    digest = hmac.digest(key, struct.pack(">Q", int(now // step)), "sha1")
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** digits).zfill(digits)


def _site(entry: str, name: str | None = None) -> tuple[str | None, str, int | None]:
    """(scheme or None, host, port or None) of a login's site entry: a bare
    host (`example.com`), a host with port, or an origin/URL. `name` is the secret the entry
    belongs to, named in the error."""
    where = f"secret {_shown(name)}: " if name is not None else ""
    text = entry.strip().lower()
    if "://" not in text:
        text = "//" + text
    try:
        parts = urlsplit(text)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise SecretsError(f"{where}a login site is not a host or origin") from None
    scheme = parts.scheme or None
    if scheme not in (None, "http", "https") or not host or not _HOST.match(host):
        raise SecretsError(f"{where}a login site is not a host or origin")
    return scheme, host, port


def site_allows(sites: tuple[str, ...], origin: str) -> bool:
    """May a login with these sites be typed on a page of `origin`?

    A site entry covers its own host and the hosts within it. A bare host
    means https (plain http only for localhost, which is not an interception
    risk); an entry written with a scheme or port must match those as well.
    An opaque origin ("null"), any non-web scheme, or an unparsable one is
    never allowed.
    """
    try:
        page = urlsplit(origin)
        page_host, page_port = page.hostname, page.port
    except ValueError:
        return False
    if page.scheme not in ("http", "https") or not page_host:
        return False
    page_host = page_host.lower()
    default = 443 if page.scheme == "https" else 80
    for entry in sites:
        scheme, host, port = _site(entry)
        if page_host != host and not page_host.endswith("." + host):
            continue
        if scheme is not None and scheme != page.scheme:
            continue
        if port is not None and port != (page_port or default):
            continue
        if scheme is None and page.scheme != "https" and host not in ("localhost", "127.0.0.1"):
            continue
        return True
    return False


def _string(record: dict, key: str, name: str, required: bool = True) -> str | None:
    value = record.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value:
        raise SecretsError(f"secret {_shown(name)}: {key} must be a non-empty string")
    return value


def _shown(name: str) -> str:
    return re.sub(r"[^\x20-\x7e]", "?", name)[:64]


class SecretStore:
    """The set, and everything derived from it. Replaced whole, atomically."""

    def __init__(self):
        self.variables: dict[str, str] = {}
        self.logins: dict[str, Login] = {}
        self._needles: list[tuple[str, str]] = []
        self._encoded: list[bytes] | None = None  # `_needles` as bytes, built on use
        self._listeners: list = []
        # Values a live job still holds in its environment after the set was
        # replaced: masked until that job ends. lease id -> values.
        self._held: dict[int, frozenset[str]] = {}
        self._lease_ids = 0
        # Short-lived values (a generated TOTP code): value -> monotonic expiry.
        self._timed: dict[str, float] = {}
        self._next_expiry = float("inf")

    # -- loading --------------------------------------------------------------

    def replace(self, payload) -> dict:
        """Take the whole set or none of it. Returns counts, never values."""
        if not isinstance(payload, dict):
            raise SecretsError("the body must be a JSON object of name to secret")
        variables: dict[str, str] = {}
        logins: dict[str, Login] = {}
        for name, value in payload.items():
            if not isinstance(name, str) or not name:
                raise SecretsError("a secret needs a non-empty name")
            if isinstance(value, str):
                if "\0" in value:  # an environment cannot hold a NUL
                    raise SecretsError(
                        f"secret {_shown(name)}: value must not contain a NUL character")
                variables[name] = value
            elif isinstance(value, dict):
                kind = value.get("kind")
                if kind == "login":
                    logins[name] = self._login(name, value)
                elif kind == "passkey":
                    raise SecretsError(
                        f"secret {_shown(name)}: passkeys are not supported; "
                        "remove it from the set")
                else:
                    raise SecretsError(f"secret {_shown(name)}: unknown kind in the \"kind\" field")
            else:
                raise SecretsError(f"secret {_shown(name)}: must be a string or a typed record")
        self.variables, self.logins = variables, logins
        self._rebuild()
        for listener in list(self._listeners):
            listener()
        return {"variables": len(variables), "logins": len(logins)}

    @staticmethod
    def _login(name: str, record: dict) -> Login:
        sites = record.get("sites")
        if (not isinstance(sites, list) or not sites
                or not all(isinstance(s, str) and s.strip() for s in sites)):
            raise SecretsError(f"secret {_shown(name)}: sites must be a non-empty list of hosts")
        for site in sites:
            _site(site, name)
        username = _string(record, "username", name)
        password = _string(record, "password", name)
        totp = _string(record, "totp", name, required=False)
        if totp is not None:
            try:
                totp_code(totp, 0)
            except ToolError:
                raise SecretsError(f"secret {_shown(name)}: totp is not valid base32") from None
        return Login(name, tuple(s.strip() for s in sites), username, password, totp)

    def on_change(self, listener) -> None:
        self._listeners.append(listener)

    # -- redaction ------------------------------------------------------------

    def _values(self) -> set[str]:
        values = set(self.variables.values()) | set(self._timed)
        for held in self._held.values():
            values |= held
        for login in self.logins.values():
            values.update((login.username, login.password))
            if login.totp:
                values.add(login.totp)
        return {v for v in values if v}

    def _rebuild(self) -> None:
        # Longest first, so a value that holds another is masked whole. Each
        # value is also masked in every spelling a JSON string body can give
        # it: \uXXXX in either case, the short escapes, and \/.
        needles = set()
        for value in self._values():
            needles.add(value)
            for ascii_only in (False, True):
                body = json.dumps(value, ensure_ascii=ascii_only)[1:-1]
                for form in (body, body.replace("/", "\\/")):
                    needles.add(form)
                    needles.add(re.sub(r"\\u([0-9a-f]{4})",
                                       lambda m: "\\u" + m.group(1).upper(), form))
        self._needles = [(n, REDACTED) for n in sorted(needles, key=len, reverse=True)]
        self._encoded = None

    def hold(self, values) -> int:
        """Keep `values` masked until `release(lease)`, whatever replaces the
        set meanwhile: a running job still has them in its environment."""
        self._lease_ids += 1
        self._held[self._lease_ids] = frozenset(v for v in values if v)
        self._rebuild()
        return self._lease_ids

    def release(self, lease: int) -> None:
        if self._held.pop(lease, None) is not None:
            self._rebuild()

    def remember_for(self, value: str, seconds: float) -> None:
        """Mask a generated value (a TOTP code) for `seconds` from now."""
        if not value:
            return
        expiry = time.monotonic() + seconds
        self._timed[value] = max(expiry, self._timed.get(value, 0.0))
        self._next_expiry = min(self._next_expiry, self._timed[value])
        self._rebuild()

    def _prune(self) -> None:
        if self._next_expiry == float("inf") or time.monotonic() < self._next_expiry:
            return
        now = time.monotonic()
        self._timed = {v: t for v, t in self._timed.items() if t > now}
        self._next_expiry = min(self._timed.values(), default=float("inf"))
        self._rebuild()

    def _live_needles(self) -> list[bytes]:
        self._prune()
        if self._encoded is None:
            self._encoded = [n.encode("utf-8") for n, _ in self._needles]
        return self._encoded

    def byte_masker(self) -> "ByteMask":
        """A streaming masker that asks for the needles as they stand at each
        chunk, so a value granted mid-stream is masked from then on."""
        return ByteMask(self._live_needles)

    def redact_bytes(self, data: bytes) -> bytes:
        """`data` with every live needle (UTF-8 and JSON-escaped spellings)
        replaced by the mask."""
        mask = REDACTED.encode()
        for needle in self._live_needles():
            if needle in data:
                data = data.replace(needle, mask)
        return data

    def redact(self, text: str) -> str:
        self._prune()
        for needle, mask in self._needles:
            if needle in text:
                text = text.replace(needle, mask)
        return text

    def redact_json(self, node):
        if isinstance(node, str):
            return self.redact(node)
        if isinstance(node, list):
            return [self.redact_json(v) for v in node]
        if isinstance(node, dict):
            return {self.redact(k) if isinstance(k, str) else k: self.redact_json(v)
                    for k, v in node.items()}
        return node

    def redact_result(self, result: dict) -> dict:
        """An MCP result with every secret masked in its text and structured
        content. Image blocks are pixels and pass as they are."""
        if not self._needles:
            return result
        out = dict(result)
        out["content"] = [
            {**block, "text": self.redact(block["text"])} if block.get("type") == "text"
            and isinstance(block.get("text"), str) else block
            for block in result.get("content", [])]
        if "structuredContent" in result:
            out["structuredContent"] = self.redact_json(result["structuredContent"])
        return out

    def log_filter(self) -> logging.Filter:
        return SecretMask(self)


class ByteMask:
    """Masks needles in a byte stream, holding back the tail that could be the
    start of one. Best-effort: a value the file holds in another encoding
    (base64, split, compressed) is not seen."""

    def __init__(self, source):
        self._source = source  # () -> the needles as they stand now
        self._mask = REDACTED.encode()
        self._carry = b""

    def _replace(self, data: bytes, needles: list[bytes]) -> bytes:
        for needle in needles:
            if needle in data:
                data = data.replace(needle, self._mask)
        return data

    def feed(self, chunk: bytes) -> bytes:
        needles = self._source()
        keep = max((len(n) for n in needles), default=1) - 1
        data = self._replace(self._carry + chunk, needles)
        if keep and len(data) > keep:
            self._carry, data = data[-keep:], data[:-keep]
            return data
        if keep:
            self._carry, data = data, b""
            return data
        self._carry = b""
        return data

    def flush(self) -> bytes:
        data, self._carry = self._replace(self._carry, self._source()), b""
        return data


class SecretMask(logging.Filter):
    """Masks granted values in a log record's message and traceback."""

    def __init__(self, store: SecretStore):
        super().__init__()
        self.store = store

    def filter(self, record: logging.LogRecord) -> bool:
        store = self.store
        if not store._needles:
            return True
        message = record.getMessage()
        masked = store.redact(message)
        if masked != message:
            record.msg, record.args = masked, ()
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = store.redact(record.exc_text)
            record.exc_info = None
        if record.stack_info:
            record.stack_info = store.redact(record.stack_info)
        return True
