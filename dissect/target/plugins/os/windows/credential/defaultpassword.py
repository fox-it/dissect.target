from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.cstruct import cstruct

from dissect.target.exceptions import RegistryKeyNotFoundError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.os.windows.credential.credential import WindowsCredentialPlugin
from dissect.target.plugins.os.windows.dpapi.keyprovider.defaultpassword.defaultpassword import (
    DefaultPasswordKeyProvider,
)
from dissect.target.plugins.os.windows.lsa import LSAPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

defaultpassword_def = """
struct DefaultPassword {
    DWORD   length;
    char    flags[4*3];
    WCHAR   data[length/2];
    char    checksum_or_guid[0x10];
};
"""

c_defaultpassword = cstruct().load(defaultpassword_def)

DefaultPasswordRecord = TargetRecordDescriptor(
    "windows/credential/default_password",
    [
        ("datetime", "ts_mtime"),
        ("string", "default_password"),
        ("path", "source"),
    ]
)


class DefaultPasswordPlugin(WindowsCredentialPlugin):
    """Windows LSA DefaultPassword plugin."""

    __namespace__ = "defaultpassword"

    def check_compatible(self) -> None:
        if not self.target.has_function("lsa"):
            raise UnsupportedPluginError("LSA plugin not available on target")

    @export(record=DefaultPasswordRecord)
    def defaultpassword(self) -> Iterator[DefaultPasswordRecord]:
        """Yield decrypted Windows LSA DefaultPassword records.

        Extracts decrypted ``DefaultPassword`` values from the LSA.

        References:
            - https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon
        """

        # Search for DefaultPassword values in the LSA
        for secret in ["DefaultPassword", "DefaultPassword_OldVal"]:
            if default_pass := self.target.lsa._secrets.get(secret):

                # Ignore irrelevant DefaultPassword references
                if "TBAL_{".encode("utf-16-le") in default_pass:
                    continue

                ts = None
                try:
                    ts = self.target.registry.key(
                        f"{LSAPlugin.SECURITY_POLICY_KEY}\\Secrets\\{secret.replace('_OldVal', '')}"
                    ).ts
                except RegistryKeyNotFoundError:
                    pass

                if default_pass.startswith(b"\x00" * 16) and len(default_pass) == 32:
                    yield DefaultPasswordRecord(
                        ts_mtime=ts,
                        default_password=default_pass[16:32].hex(),
                        source=f"HKLM\\SECURITY\\Policy\\Secrets\\{secret}",
                        _target=self.target,
                    )
                    continue

                try:
                    value = c_defaultpassword.DefaultPassword(default_pass).data
                except Exception as e:
                    self.target.log.warning("Failed to parse LSA %s value (%r): %s", secret, default_pass, e)
                    self.target.log.debug("", exc_info=e)
                    continue

                yield DefaultPasswordRecord(
                    ts_mtime=ts,
                    default_password=value,
                    source=f"HKLM\\SECURITY\\Policy\\Secrets\\{secret}",
                    _target=self.target,
                )
