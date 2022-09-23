import re

from dissect.target.exceptions import UnsupportedPluginError
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
    """Return Microsoft Office Trusted Document registry keys.

    Trusted Document keys are used by Microsoft to cache for a document that the user enabled the editing and/or macros.
    Therefore, this may reveal if for any malicious Office document the macros have been enabled.
    """

    KEY = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office"

    def check_compatible(self) -> None:
        if not len(list(self.target.registry.key(self.KEY))) > 0:
            raise UnsupportedPluginError("No Trusted Document keys found")

    def _iterate_keys(self):
        """Yields all Microsoft Office keys, regardless of the version and application and looks for the Security key"""
        for key in self.target.registry.iterkeys(self.KEY):
            for version_key in key.subkeys():
                for application_key in version_key.subkeys():
                    for application_subkey in application_key.subkeys():
                        if application_subkey.name == "Security":
                            yield from application_subkey.subkeys()

    @export(record=TrustedDocsRecord)
    def trusteddocs(self):
        """Return Microsoft Office Trusted Document registry keys for all Office applications"""
        user = self.target.registry.get_user(self.target.registry.key(self.KEY))
        for security_key in self._iterate_keys():
            pattern = re.compile(r"[0-9]\\(.*)\\Security")
            application = pattern.search(security_key.path).group(1)

            if security_key.name == "Trusted Documents":
                for trusted_docs_key in security_key.subkeys():
                    for value in trusted_docs_key.values():
                        yield TrustedDocsRecord(
                            ts=trusted_docs_key.ts,
                            type=value.type,
                            application=application,
                            document_path=value.name,
                            value=value.value,
                            _key=trusted_docs_key,
                            _user=user,
                            _target=self.target,
                        )
