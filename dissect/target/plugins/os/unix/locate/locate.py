from __future__ import annotations

from dissect.target.plugin import NamespacePlugin


class BaseLocatePlugin(NamespacePlugin):
    __namespace__ = "locate"
