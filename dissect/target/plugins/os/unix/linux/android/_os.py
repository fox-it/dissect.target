from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers import configutil
from dissect.target.helpers.record import AndroidUserRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.plugins.os.unix.linux.android.util.abx import AbxFile, AbxSettingsFile

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class AndroidPlugin(LinuxPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self.target = target

        self.build_prop_paths = set(find_build_props(self.target.fs))
        self.props = {}

        for build_prop in self.build_prop_paths:
            try:
                self.props.update(
                    configutil.parse(
                        build_prop,
                        hint="meta_bare",
                        separator=("=",),
                        comment_prefixes=("#",),
                    ).parsed_data
                )
            except Exception as e:  # noqa: PERF203
                self.target.log.warning("Unable to parse Android build.prop file %s: %s", build_prop, e)

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        ANDROID_PATHS = (
            "data",
            "system",
            "vendor",
            "product",
        )

        for fs in target.filesystems:
            if all(fs.exists(p) for p in ANDROID_PATHS) and any(find_build_props(fs)):
                return fs
        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
        """Return the likely hostname of this Android device."""
        # Try the first user's ``device_name`` first
        if (path := self.target.fs.path("/data/system/users/0/settings_global.xml")).is_file():
            try:
                return AbxSettingsFile(path).get("device_name")
            except ValueError:
                pass

        # Try ``net.hostname``
        if net_hostname := self.props.get("net.hostname"):
            return net_hostname

        # Fallback to ``ro.build.host`` property
        return self.props.get("ro.build.host")

    @export(property=True)
    def ips(self) -> list[str]:
        return []

    @export(property=True)
    def version(self) -> str:
        full_version = "Android"

        release_version = self.props.get("ro.build.version.release")
        if release_version := self.props.get("ro.build.version.release"):
            full_version += f" {release_version}"

        if security_patch_version := self.props.get("ro.build.version.security_patch"):
            full_version += f" ({security_patch_version})"

        return full_version

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.ANDROID.value

    @export(record=AndroidUserRecord)
    def users(self) -> Iterator[AndroidUserRecord]:
        """Yield all configured users of this Android system."""
        if not (users_dir := self.target.fs.path("/data/system/users")).is_dir():
            return

        for path in users_dir.iterdir():
            # Parse the /data/system/users/$id.xml ABX file for basic user information.
            # Currently we do not parse /data/system/users/0/settings_(config|global|secure).xml
            if not path.is_dir() or not (file := path.parent.joinpath(path.name + ".xml")).is_file():
                continue
            try:
                abx = AbxFile(file)
                user = abx.tree.find(".")
            except ValueError as e:
                self.target.log.warning("Unable to parse %s: %s", file, e)
                continue

            id = None
            name = None
            try:
                id = user.attrib["id"]
                name = user.find("./name").text
            except Exception:
                pass

            yield AndroidUserRecord(
                name=name,
                uid=id,
                home=f"/data/media/{id}",
                last_login=user.attrib["lastLoggedIn"] / 1000,
                last_foreground=user.attrib["lastEnteredForeground"] / 1000,
                flags=user.attrib["flags"],
                usertype=user.attrib["type"],
                source=file,
                _target=self.target,
            )

def find_build_props(fs: Filesystem) -> Iterator[Path]:
    """Search for Android ``build.prop`` files on the provided :class:`Filesystem`."""
    if (root_prop := fs.path("/build.prop")).is_file():
        yield root_prop

    for prop in fs.path("/").glob("*/build.prop"):
        if prop.is_file():
            yield prop
