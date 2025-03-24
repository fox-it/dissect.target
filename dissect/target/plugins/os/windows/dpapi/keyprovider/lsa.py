from typing import Iterator

from dissect.cstruct import cstruct

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import export
from dissect.target.plugins.os.windows.dpapi.keyprovider.keyprovider import (
    KeyProviderPlugin,
)

defaultpassword_def = """
struct DefaultPassword {
    DWORD   length;
    char    flags[4*3];
    WCHAR   data[length/2];
    char    checksum_or_guid[0x10];
};
"""

c_defaultpassword = cstruct().load(defaultpassword_def)


class LSADefaultPasswordKeyProviderPlugin(KeyProviderPlugin):
    """Windows LSA DefaultPassword key provider plugin."""

    __namespace__ = "_dpapi_keyprovider_lsa_defaultpassword"

    def check_compatible(self) -> None:
        if not self.target.has_function("lsa"):
            raise UnsupportedPluginError("LSA plugin not available on target")

    @export(output="yield")
    def keys(self) -> Iterator[tuple[str, str]]:
        """Yield Windows LSA DefaultPassword strings.

        Currently extracts decrypted ``DefaultPassword`` values from LSA.
        Does not yet parse ``HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DefaultPassword``.

        Resources:
            - https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon
        """

        for secret in ["DefaultPassword", "DefaultPassword_OldVal"]:
            if default_pass := self.target.lsa._secrets.get(secret):
                try:
                    value = c_defaultpassword.DefaultPassword(default_pass).data
                except Exception:
                    self.target.log.warning("Failed to parse LSA %s value", secret)
                    continue
                yield self.__namespace__, value
