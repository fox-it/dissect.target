import plistlib
from typing import Iterator

from dissect.util.plist import NSKeyedArchiver

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import IOSApplicationRecord
from dissect.target.plugin import OperatingSystem, Plugin, export


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

            yield IOSApplicationRecord(
                ts_installed=bundle.get("installDate"),
                name=metadata.get("itemName"),
                version=metadata.get("bundleShortVersionString"),
                author=metadata.get("artistName"),
                type=metadata.get("kind"),
                path=app_dir,
                _target=self.target,
            )
