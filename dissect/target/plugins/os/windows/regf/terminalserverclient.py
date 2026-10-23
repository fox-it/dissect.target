from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


TerminalServerClientRecord = create_extended_descriptor(
    [RegistryRecordDescriptorExtension, UserRecordDescriptorExtension]
)(
    "windows/registry/terminal_server_client/server",
    [
        ("datetime", "ts"),
        ("string", "server"),
        ("string", "username_hint"),
    ],
)


class TerminalServerClientPlugin(Plugin):
    """Parse cached Microsoft Terminal Server Client server username hints."""

    KEY = "HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers"

    def check_compatible(self) -> None:
        if not any(self.target.registry.keys(self.KEY)):
            raise UnsupportedPluginError("No Terminal Server Client Servers registry keys found")

    @export(record=TerminalServerClientRecord)
    def terminal_server_client(self) -> Iterator[TerminalServerClientRecord]:
        """Return cached Microsoft Terminal Server Client server username hints.

        The ``HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers`` registry key
        contains server names previously entered in the Terminal Server Client GUI. A
        server subkey can contain a ``UsernameHint`` value with a cached username.

        These values do not prove that an RDP connection or connection attempt occurred.
        Corroborate them with other artifacts, such as Windows event logs.

        References:
            - https://www.magnetforensics.com/blog/rdp-artifacts-in-incident-response/
        """
        for servers_key in self.target.registry.keys(self.KEY):
            user = self.target.registry.get_user(servers_key)

            for server_key in servers_key.subkeys():
                try:
                    username_hint = server_key.value("UsernameHint").value
                except RegistryError:
                    continue

                yield TerminalServerClientRecord(
                    ts=server_key.ts,
                    server=server_key.name,
                    username_hint=username_hint,
                    _target=self.target,
                    _key=server_key,
                    _user=user,
                )
