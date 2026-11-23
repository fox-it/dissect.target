from __future__ import annotations

from dissect.target.plugin import NamespacePlugin


class WindowsCredentialPlugin(NamespacePlugin):
    __namespace__ = "credential"
