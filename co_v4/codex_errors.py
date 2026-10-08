"""Sanitized Codex host admission errors."""


class HostUnverified(RuntimeError):
    """Fixed diagnostic only; never include paths, credentials or Native text."""
