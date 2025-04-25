import plistlib
from collections.abc import Iterator
from pathlib import Path

from dissect.util.plist import NSKeyedArchiver

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import (
    COMMON_APPLICATION_FIELDS,
    TargetRecordDescriptor,
)
from dissect.target.plugin import OperatingSystem, Plugin, export

IOSApplicationRecord = TargetRecordDescriptor(
    "ios/application",
    COMMON_APPLICATION_FIELDS,
)


class IOSApplicationsPlugin(Plugin):
    """iOS applications plugin."""

    PATH = "/private/var/containers/Bundle/Application"

    def check_compatible(self) -> None:
        if self.target.os != OperatingSystem.IOS or not self.target.fs.path(self.PATH).exists():
            raise UnsupportedPluginError("Target is not iOS or no Bundle Application folder found")

    @export(record=IOSApplicationRecord)
    def applications(self) -> Iterator[IOSApplicationRecord]:
        """Yield installed iOS apps."""

        for app_dir in self.target.fs.path(self.PATH).glob("*"):
            if not app_dir.is_dir():
                continue

            metadata = {}
            if (metadata_file := app_dir.joinpath("iTunesMetadata.plist")).exists():
                metadata = plistlib.load(metadata_file.open("rb"))

            bundle = {}
            if (bundle_file := app_dir.joinpath("BundleMetadata.plist")).exists():
                bundle = NSKeyedArchiver(bundle_file.open("rb"))["root"]

            # System apps do not have a iTunesMetadata.plist file.
            info = {}
            if not metadata and (info_file := next(app_dir.glob("*.app/Info.plist"), None)):
                info = plistlib.load(info_file.open("rb"))
                if info.get("CFBundleIdentifier", "").startswith("com.apple."):
                    info["author"] = "Apple"
                    info["type"] = "system"

            # Ultimate fallback to application name
            if not info.get("CFBundleDisplayName") and not metadata.get("itemName"):
                metadata["itemName"] = next(app_dir.glob("*.app"), Path()).name.removesuffix(".app")

            yield IOSApplicationRecord(
                ts_installed=bundle.get("installDate"),
                name=metadata.get("itemName") or info.get("CFBundleDisplayName"),
                version=metadata.get("bundleShortVersionString") or info.get("CFBundleShortVersionString"),
                author=metadata.get("artistName") or info.get("author"),
                type=metadata.get("kind") or info.get("type"),
                path=app_dir,
                _target=self.target,
            )
