from __future__ import annotations

from dissect.target.plugin import NamespacePlugin


class OpenVPNPlugin(NamespacePlugin):
    """OpenVPN namespace plugin."""

    __namespace__ = "openvpn"
