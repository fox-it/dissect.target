from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_plist_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

LoginItemsRecord = TargetRecordDescriptor(
    "macos/login_items",
    [
        ("string", "associated_bundle_identifiers"),
        ("bytes", "bookmark"),
        ("string", "bundle_identifier"),
        ("string", "container"),
        ("string", "designated_requirement"),
        ("string", "developer_name"),
        ("string", "login_item_disposition"),
        ("datetime", "executable_modification_date"),
        ("path", "executable_path"),
        ("varint", "flags"),
        ("varint", "generation"),
        ("string", "identifier"),
        ("bytes", "lightweight_requirement"),
        ("datetime", "modification_date"),
        ("string", "name"),
        ("string", "program_arguments"),
        ("string", "sha256"),
        ("string", "team_identifier"),
        ("string", "login_item_type"),
        ("string", "url"),
        ("string", "uuid"),
        ("string[]", "items"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

LoginItemsMetadataRecord = TargetRecordDescriptor(
    "macos/login_items/metadata",
    [
        ("varint", "generation"),
        ("varint", "background_app_refresh_load_count"),
        ("boolean", "launch_services_items_imported"),
        ("boolean", "service_management_login_items_migrated"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

LoginItemsRecords = (LoginItemsRecord, LoginItemsMetadataRecord)

FIELD_MAPPINGS = {
    "associatedBundleIdentifiers": "associated_bundle_identifiers",
    "bundleIdentifier": "bundle_identifier",
    "designatedRequirement": "designated_requirement",
    "developerName": "developer_name",
    "disposition": "login_item_disposition",
    "executableModificationDate": "executable_modification_date",
    "executablePath": "executable_path",
    "lightweightRequirement": "lightweight_requirement",
    "modificationDate": "modification_date",
    "programArguments": "program_arguments",
    "teamIdentifier": "team_identifier",
    "type": "login_item_type",
    "backgroundAppRefreshLoadCount": "background_app_refresh_load_count",
    "launchServicesItemsImported": "launch_services_items_imported",
    "serviceManagementLoginItemsMigrated": "service_management_login_items_migrated",
}

VALUE_MAPPINGS = {
    "login_item_disposition": {
        1: "Enabled",
        2: "Allowed",
        4: "Hidden",
        8: "Notified",
    },
    "login_item_type": {
        1: "user item",
        2: "app",
        4: "login item",
        8: "agent",
        16: "daemon",
        32: "developer",
        64: "spotlight",
        2048: "quicklook",
        65536: "legacy",
        524288: "curated",
    },
}

CONVERT_TIMESTAMPS = {
    "modification_date": "2001",
}


class LoginItemsPlugin(Plugin):
    """macOS login items plugin.

    Parses macOS login items and background task entries from plist and BTM
    files, which are used by the system to launch applications and services
    at user login.

    References:
        - https://www.swiftforensics.com/2025/01/macapt-update-to-btm-processing.html
        - https://developer.apple.com/documentation/corefoundation/cfurl
    """

    SYSTEM_LOGIN_ITEMS_PATHS = ("/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm",)

    USER_LOGIN_ITEMS_PATHS = (
        "Library/Preferences/com.apple.loginitems.plist",
        "Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.login_items_files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.login_items_files):
            raise UnsupportedPluginError("No Login Items files found")

    def _find_files(self) -> set:
        login_items_files = set()
        for pattern in self.SYSTEM_LOGIN_ITEMS_PATHS:
            for path in self.target.fs.glob(pattern):
                login_items_files.add(path)

        for _, path in _build_userdirs(self, self.USER_LOGIN_ITEMS_PATHS):
            login_items_files.add(path)

        return login_items_files

    @export(record=LoginItemsRecord)
    def login_items(self) -> Iterator[LoginItemsRecord]:
        """Return macOS login items and background task entries.

        Yields the following record types extracted from the
        backgrounditems.btm and com.apple.loginitems.plist files:

        .. code-block:: text

            LoginItemsRecord:
                associated_bundle_identifiers (string): Associated bundle identifiers.
                bookmark (bytes): CFURL bookmark data referencing a file-system resource.
                bundle_identifier (string): Bundle identifier of the item.
                container (string): Containing app or bundle.
                designated_requirement (string): Code signing designated requirement.
                developer_name (string): Developer name.
                login_item_disposition (string): Numeric value describing state.
                executable_modification_date (datetime): Last modification time of the executable.
                executable_path (path): Path to the executable.
                flags (varint): Additional flags associated with the item.
                generation (varint): Generation identifier of the record.
                identifier (string): Unique identifier for the item.
                lightweight_requirement (bytes): Lightweight code signing requirement data.
                modification_date (datetime): Last modification timestamp of the record.
                name (string): Name of the item.
                program_arguments (string): Program arguments for execution.
                sha256 (string): SHA256 hash of the executable.
                team_identifier (string): Apple developer team identifier.
                login_item_type (string): Numeric value describing the item type.
                url (string): URL associated with the item.
                uuid (string): Universally unique identifier.
                items (string[]): List of items.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the backgrounditems.btm or com.apple.loginitems.plist file.

            LoginItemsMetadataRecord:
                generation (varint): Metadata generation value.
                background_app_refresh_load_count (varint): Background app refresh load count.
                launch_services_items_imported (boolean): Indicates LaunchServices import.
                service_management_login_items_migrated (boolean): Indicates migration status.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the backgrounditems.btm or com.apple.loginitems.plist file.
        """
        yield from build_plist_records(
            self,
            self.login_items_files,
            LoginItemsRecords,
            field_mappings=FIELD_MAPPINGS,
            value_mappings=VALUE_MAPPINGS,
            convert_timestamps=CONVERT_TIMESTAMPS,
        )
