"""Loom Computer: the MCP server and viewer for a containerized Linux desktop."""

from pathlib import Path

# The release this image is. The VERSION file at the repo root is the single
# source of truth: the release workflow, the Dockerfile's label and build arg,
# and the guide this server serves all read it (the image carries a copy at
# the same relative path). Matches Loom's COMPUTER_VERSION floor.
VERSION = (Path(__file__).resolve().parent.parent / "VERSION").read_text().strip()
