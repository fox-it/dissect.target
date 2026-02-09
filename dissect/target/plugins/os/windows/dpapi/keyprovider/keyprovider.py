from __future__ import annotations

from dissect.target.plugin import InternalNamespacePlugin


class KeyProviderPlugin(InternalNamespacePlugin):
    """Key provider plugin for DPAPI."""

    __namespace__ = "dpapi.keyprovider"

    def check_compatible(self) -> None:
        return None
