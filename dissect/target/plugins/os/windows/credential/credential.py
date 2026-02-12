from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugin import NamespacePlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


class WindowsCredentialPlugin(NamespacePlugin):
    __namespace__ = "credential"

    def __init__(self, target: Target):
        super().__init__(target)
