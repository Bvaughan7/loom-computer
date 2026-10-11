"""One exception for "the tool refused, and here is why" (answered as isError)."""


class ToolError(Exception):
    """A failure the agent should read: the message is the tool's answer."""
