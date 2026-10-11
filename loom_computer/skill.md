---
name: loom-computer
description: Drive the Loom Computer, a containerized Linux desktop, through its MCP tools - shell, files, browser and capture.
---

# Loom Computer

A Linux desktop (1280x800) with a real Chromium. You work as the unprivileged
`agent` user. Your workspace is `/home/agent/workspace`; it persists, the rest
of the container may not. Five tools:

| Tool | Use |
| --- | --- |
| `shell` | Run a command and wait for it. |
| `files` | Read, write and list files in the workspace; run a script file. |
| `browser` | Drive Chromium: navigate, read, fill, click. |
| `capture` | Look: a screenshot, or the page's accessibility tree. |
| `state` | `{"action": "guide"}` answers this document. |

Tool failures come back as an error result whose text says what was wrong;
fix the call and try again.

## shell

Arguments: exactly one of `command` (a string, run by `bash -c`, so pipes,
globs and `&&` work) or `argv` (a list run directly with no shell: use it
when an argument holds text you do not want a shell to interpret). Optional
`cwd` (default the workspace; relative paths start there) and `timeout`
(seconds, default 120, at most 3600).

Answer: `exit_code`, `stdout`, `stderr`, `timed_out`, `truncated`,
`duration_s`. A non-zero exit is a normal answer, not an error. On timeout
the command's whole process tree is killed and `exit_code` is null. Output
over about 190 KB per stream keeps its start and end.

Jobs have no stdin. When the command exits, anything it left running in its
process group is killed too; start something that must outlive the call
with `setsid`. Jobs see a small fixed environment (`PATH`, `HOME`, `DISPLAY`
...) plus any `KEY=VALUE` lines in `/home/agent/workspace/.loom/env`; they do
not inherit the computer's own environment. Because `DISPLAY` is set, a GUI
program you start shows up on the desktop.

## files

`action` is one of:

- `read` `{path}`: text (UTF-8) up to 1 MiB; `encoding: "base64"` for binary.
- `write` `{path, content}`: creates parent directories and replaces the
  file; `append: true` appends; `encoding: "base64"` writes binary. Up to 8 MiB.
- `list` `{path}` (default `.`): name, type (file, dir, symlink, other), size.
- `run` `{path, args?, cwd?, timeout?}`: runs the script as a job exactly like
  `shell` and answers the same. `.py` runs under `python3`, `.sh` under
  `bash`; any other file must be executable.

Paths are relative to the workspace or absolute inside it. Anything that
resolves outside it, by `..` or by a symlink, is refused. For files elsewhere
use `shell`.

## browser

Acts on the active tab of the desktop's Chromium - the same one the person
sees in the viewer. `action` is one of:

- `navigate` `{url}`: `http:`, `https:`, `file:`, `about:`, `data:`. Waits for
  the page to load (up to 30 s; `loaded` says whether it did). Answers `url`
  and `title`.
- `title`: the current `url` and `title`.
- `text` `{selector?}`: the visible text of the page, or of the first element
  matching the CSS selector (up to 100,000 characters).
- `fill` `{selector, value}`: enters `value` into an input, textarea, select
  or contenteditable element, firing `input` and `change` as typing would.
  `fill` `{selector, secret, field?}` types a granted login instead: `secret`
  is the login's name and `field` is `username`, `password` (default) or
  `totp` (the current code). It is refused unless the page is one of the
  login's own sites; you never see the value.
- `click` `{selector}`: scrolls the element into view and clicks its centre
  with a real mouse event.

Selectors are CSS (`#login`, `input[name=email]`, `button.primary`). To find
them, use `browser text` or `capture` with `mode: "tree"`.

## capture

`mode` is one of:

- `image`: a screenshot of the desktop, scaled so the longer edge is at most
  1568 px. The text beside it says the scale.
- `png`: the same, at full size.
- `tree`: the active browser page's accessibility tree as text (roles, names,
  values), one node per line. `window` and `region` do not apply.

`window` narrows `image` and `png` to one window: a 1-based number, or a part
of its title or class (`"chromium"`). An unknown window is refused and the
answer lists the windows. `region` is `[x, y, width, height]` in pixels,
relative to the window if one is given, else to the screen; it is clipped to
the screen. It captures what is on screen, so a window covered by another
shows the cover.

## secrets

The person may grant you secrets. You never see their values: every tool
answer has them replaced by `[REDACTED]`.

- A *variable* is an environment variable of every `shell` and `files run`
  job, under its name (`$NAME`).
- A *login* is typed with `browser fill` and `secret`, only on its own sites.
  Navigate there first; on any other page the fill is refused.
- A *passkey* is already in the browser: a site's passkey sign-in is answered
  without anything typed. Nothing you do can create a passkey.

## state

`{"action": "guide"}` answers `version`, `sha256` and `skill` (this
document). Other actions are refused.
