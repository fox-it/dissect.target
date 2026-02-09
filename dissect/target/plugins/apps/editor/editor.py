from __future__ import annotations

from dissect.target.plugin import NamespacePlugin, export

COMMON_EDITOR_FIELDS = [
    ("datetime", "ts"),
    ("string", "editor"),
    ("path", "source"),
]


class EditorPlugin(NamespacePlugin):
    """Editor plugin."""

    __namespace__ = "editor"

    @export
    def extensions(self) -> None:
        """Yields installed extensions."""
        raise NotImplementedError

    @export
    def history(self) -> None:
        """Yields history of files."""
        raise NotImplementedError
