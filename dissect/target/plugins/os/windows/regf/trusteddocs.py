import re

from dissect.target.exceptions import UnsupportedPluginError, RegistryKeyNotFoundError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

TrustedDocsRecord = create_extended_descriptor([RegistryRecordDescriptorExtension, UserRecordDescriptorExtension])(
    "windows/registry/trusteddocuments",
    [
        ("datetime", "ts"),
        ("string", "application"),
        ("varint", "type"),
        ("string", "document_path"),
        ("bytes", "value"),
    ],
)


class TrustedDocsPlugin(Plugin):
    """Plugin to obtain Microsoft Office Trusted Document registry keys."""

    KEY = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office"

    def check_compatible(self) -> None:
        if not len(list(self.target.registry.key(self.KEY))) > 0:
            raise UnsupportedPluginError("No Trusted Document keys found")

    def _find_subkey(self, key, subkey_name: str):
        try:
            searched_key = key.subkey(subkey_name)
            if searched_key.subkeys():
                yield from searched_key.subkeys()
            else:
                yield searched_key
        except RegistryKeyNotFoundError:
            pass

    def _iterate_keys(self):
        """Yields all Microsoft Office keys that contain a TrustRecords subkey."""
        for key in self.target.registry.iterkeys(self.KEY):
            for version_key in key.subkeys():
                for application_key in version_key.subkeys():
                    yield from (
                        y
                        for x in self._find_subkey(application_key, "Security")
                        for y in self._find_subkey(x, "TrustRecords")
                    )

    @export(record=TrustedDocsRecord)
    def trusteddocs(self):
        """Return Microsoft Office TrustRecords registry keys for all Office applications.

        Microsoft uses Trusted Documents to cache whether the user enabled the editing and/or macros for that document.
        Therefore, this may reveal if macros have been enabled for a malicious Office document.
        """
        user = self.target.registry.get_user(self.target.registry.key(self.KEY))
        pattern = re.compile(r"[0-9]\\(.*)\\Security")

        for key in self._iterate_keys():
            application = pattern.search(key.path).group(1)
            for value in key.values():
                yield TrustedDocsRecord(
                    ts=key.ts,
                    type=value.type,
                    application=application,
                    document_path=self.target.path.resolve(value.name),
                    value=value.value,
                    _key=key,
                    _user=user,
                    _target=self.target,
                )
