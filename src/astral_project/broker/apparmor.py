"""Deterministic AppArmor source-root include generation."""

from __future__ import annotations

from collections.abc import Iterable


def render_source_roots(roots: Iterable[str]) -> str:
    """Render exact read/traverse rules for already-authorized absolute roots."""
    values = tuple(sorted(set(roots), key=str.encode))
    if not values or any(not _safe_root(root) for root in values):
        raise ValueError("source roots must be unique safe absolute paths")
    lines: list[str] = []
    for root in values:
        escaped = _escape(root)
        lines.extend((f"{escaped}/ r,", f"{escaped}/** r,"))
    return "\n".join(lines) + "\n"


def _safe_root(root: str) -> bool:
    if not root.startswith("/") or "\x00" in root or root == "/":
        return False
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in root):
        return False
    components = root.split("/")
    return all(component not in {"", ".", ".."} for component in components[1:])


def _escape(value: str) -> str:
    escaped = set("\\ \t\n\"' *?[]{}")
    return "".join(("\\" + char) if char in escaped else char for char in value)
