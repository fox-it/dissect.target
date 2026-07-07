from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.record import EmptyRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class AndroidPlugin(LinuxPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self.target = target

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        """Detect an Android-like filesystem."""
        ANDROID_PATHS = ("data", "system", "vendor", "product")
        for fs in target.filesystems:
            if all(fs.exists(p) for p in ANDROID_PATHS):
                return fs
        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
        return self.target.property.get("ro.build.host")

    @export(property=True)
    def ips(self) -> list[str]:
        return []

    @export(property=True)
    def version(self) -> str:
        """Return the version of this Android system."""
        version = "Android"

        if release_version := self.target.property.get("ro.build.version.release"):
            version += f" {release_version}"

        if build_id := self.target.property.get("ro.build.id"):
            version += f" {build_id}"

        if security_patch_version := self.target.property.get("ro.build.version.security_patch"):
            version += f" ({security_patch_version})"

        return version

    @export(property=True)
    def architecture(self) -> str | None:
        """Return the architecture triple of this Android system."""
        for bin in (
            "/system/bin/sh",
            "/vendor/bin/sh",
        ):
            if arch := self._get_architecture(self.os, bin):
                return arch
        return None

    @export(property=True)
    def device(self) -> str | None:
        """Return the device brand, model and name of this Android system."""
        manufacturer = self.target.property.get("ro.product.vendor.manufacturer", "").capitalize()
        device = self.target.property.get("ro.product.vendor.device", "").upper()
        model = self.target.property.get("ro.product.vendor.model", "")
        _device = f"{manufacturer} {device} {model}"
        if name := self.target.property.get("ro.product.vendor.name"):
            _device += f" ({name})"

        return _device.strip() or None

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.ANDROID.value

    @export(record=EmptyRecord)
    def users(self) -> Iterator[EmptyRecord]:
        yield from ()
