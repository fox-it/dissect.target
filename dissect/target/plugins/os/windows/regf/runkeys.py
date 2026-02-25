from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

RunKeyRecord = create_extended_descriptor([RegistryRecordDescriptorExtension, UserRecordDescriptorExtension])(
    "windows/registry/run",
    [
        ("datetime", "ts"),
        ("wstring", "name"),
        ("command", "command"),
        ("string", "source"),
    ],
)


class RunKeysPlugin(Plugin):
    """Plugin that iterates various Runkey locations."""

    KEYS = (
        # System-wide ASEP
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup",
        "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",  # noqa: E501
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",  # noqa: E501
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",  # noqa: E501
        # Per user ASEP
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",  # noqa: E501
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",  # noqa: E501
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",  # noqa: E501
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
        "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup",
        "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        # Service start-up
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    )

    def check_compatible(self) -> None:
        if not next(self.target.registry.keys(self.KEYS), None):
            raise UnsupportedPluginError("No registry run key found")

    @export(record=RunKeyRecord)
    def runkeys(self) -> Iterator[RunKeyRecord]:
        """Iterate various run key locations. See source for all locations.

        Run keys (Run and RunOnce) are registry keys that make a program run when a user logs on. a Run key runs every
        time the user logs on and the RunOnce key makes the program run once and deletes the key after. Often leveraged
        as a persistence mechanism.

        References:
            - https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
            - https://attack.mitre.org/techniques/T1547/001/
            - https://www.nextron-systems.com/2025/07/29/detecting-the-most-popular-mitre-persistence-method-registry-run-keys-startup-folder/

        Yields RunKeyRecords with fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The registry key last modified timestamp.
            name (string): The run key name.
            command (command): The run key command.
            source (string): The source registry key for this run key.
        """
        for key_str in self.KEYS:
            for key in self.target.registry.keys(key_str):
                user = self.target.registry.get_user(key)
                for entry in key.values():
                    yield RunKeyRecord(
                        ts=key.ts,
                        name=entry.name,
                        command=entry.value or None,
                        source=key_str,
                        _target=self.target,
                        _key=key,
                        _user=user,
                    )
