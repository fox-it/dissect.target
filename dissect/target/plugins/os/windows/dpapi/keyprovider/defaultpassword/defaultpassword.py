from __future__ import annotations

from dissect.target.plugins.os.windows.dpapi.keyprovider.keyprovider import KeyProviderPlugin


class DefaultPasswordKeyProvider(KeyProviderPlugin):
    """DefaultPassword key provider plugin for DPAPI."""

    __namespace__ = "dpapi.keyprovider.defaultpassword"

    def check_compatible(self) -> None:
        return None
