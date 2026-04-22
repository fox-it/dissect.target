from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.ngc.provider import NGCProvider

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.plugins.os.windows.ngc.protector import NGCProtector
    from dissect.target.target import Target


NGCProviderRecord = TargetRecordDescriptor(
    "windows/ngc/provider",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("string", "user"),
        ("path", "source"),
    ],
)


class NGCPlugin(Plugin):
    """Microsoft Windows Next Generation Credential (NGC) plugin.

    Provides a modern interface for managing user credentials (PIN, biometrics, etc.), used by
    Windows Hello and WHFB / Entra ID.

    NGC can enroll key storage providers (KSPs) for each user in the following categories:
        - Microsoft Software Key Storage Provider
        - Microsoft Platform Crypto Provider
        - Microsoft Smart Card Key Storage Provider
        - Microsoft Passport Key Storage Provider

    Some of these KSPs store their key material on disk, such as the default Software KSP. Others,
    such as the Platform Crypto KSP use a different storage medium, such as the system's TPM.

    References:
        - https://github.com/tijldeneut/diana
        - https://www.insecurity.be/blog/2020/12/24/dpapi-in-depth-with-tooling-standalone-dpapi/
        - https://www.synaktiv.com/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow.html
    """

    __namespace__ = "ngc"

    PROVIDERS = "sysvol\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc"

    def __init__(self, target: Target):
        super().__init__(target)

        self.system_providers = [NGCProvider(path) for path in self.target.fs.path(self.PROVIDERS).iterdir()]

    def check_compatible(self) -> None:
        if not self.providers:
            raise UnsupportedPluginError("No NGC keys found on target")

    def find_protector(self, key_name: str) -> Iterator[NGCProtector]:
        """Find NGC Protector(s) for the given :class:`CNGKey` ``key_name``."""
        for provider in self.system_providers:
            for protector in provider.protectors:
                if protector.key_name == key_name:
                    yield protector

    @export(record=NGCProviderRecord)
    def providers(self) -> Iterator[NGCProviderRecord]:
        """Yield NGC provider records."""
        for provider in self.system_providers:
            yield NGCProviderRecord(
                ts=provider.path.lstat().st_mtime,
                name=provider.name,
                user=provider.sid,
                source=provider.path,
                _target=self.target,
            )
