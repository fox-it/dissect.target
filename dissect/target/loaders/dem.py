from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers import record
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.regutil import RegFlex
from dissect.target.loader import Loader
from dissect.target.plugin import export
from dissect.target.plugins.os.windows._os import WindowsPlugin
from dissect.target.plugins.os.windows.registry import RegistryPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target

log = logging.getLogger(__name__)

DEM_DIRS = (
    "demData",
    "demData_agt_wss",
    "demData_fbu_wss",
    "demData_wss_test",
    "demDataPP",
)

DIR_MAPPING = {
    "appdata": "AppData/Roaming",
    "localappdata": "AppData/Local",
    "recentfiles": "AppData/Roaming/Microsoft/Windows/Recent",
}


def find_dem_path(path: Path) -> Path | None:
    """Find the DEM data directory within the given path."""
    for dem in DEM_DIRS:
        dem_path = path / dem
        if dem_path.is_dir():
            return dem_path  # man

    return None


class DemLoader(Loader):
    """Load Omnissa Dynamic Environment Manager (DEM / FlexEngine) profile data.

    The ``demData`` directory contains exported application- and roaming profile data.

    Each category (e.g. ``Applications``, ``Windows Settings``) has one subdirectory per managed application or setting.

    That subdirectory can contain:
    - ``AppData/``      -> ``C:/Users/<user>/AppData/Roaming/``
    - ``LocalAppData/`` -> ``C:/Users/<user>/AppData/Local/``
    - ``RecentFiles/``  -> ``C:/Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/``
    - ``Registry/``     -> ``HKEY_CURRENT_USER`` registry entries (RegFlex ``.reg`` files)

    The ``backup/`` and ``FlexRepository/`` subdirectories are explicitly ignored for now.

    Resources:
    - https://docs.omnissa.com/bundle/DEMInstallConfigGuideV2209/page/IntroductiontoDynamicEnvironmentManager.html
    """

    @staticmethod
    def detect(path: Path) -> bool:
        return find_dem_path(path) is not None

    def map(self, target: Target) -> None:
        dem_path = find_dem_path(self.absolute_path)
        username = self.absolute_path.name

        vfs = VirtualFilesystem(case_sensitive=False)
        target.filesystems.add(vfs)
        regflex = RegFlex()

        # <category>/<app>/<entry>
        # avoid nested looping and is_dir checks
        for entry in dem_path.glob("*/*/*"):
            if not entry.is_dir():
                continue

            name = entry.name.lower()
            if name in DIR_MAPPING:
                for file in entry.rglob("*"):
                    if file.is_file():
                        dest = f"Users/{username}/{DIR_MAPPING[name]}/{file.relative_to(entry).as_posix()}"
                        vfs.map_file(dest, file)

            elif name == "registry":
                for reg_file in entry.rglob("*.reg"):
                    with reg_file.open("r", encoding="utf-16") as fh:
                        regflex.map_definition(fh)

        target.props["username"] = username
        target._os_plugin = DemOSPlugin.create(target, vfs)
        target.add_plugin(RegistryPlugin, check_compatible=False)

        for name, hive in regflex.hives.items():
            target.registry.add_hive(name, "HKEY_USERS\\S-1-0-0", hive, TargetPath(target.fs, dem_path.name))


class DemOSPlugin(WindowsPlugin):
    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            for dem_dir in DEM_DIRS:
                if fs.exists(f"/{dem_dir}"):
                    return fs
        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        target.fs.case_sensitive = False
        target.fs.mount("sysvol", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str:
        return self.target.props.get("username", self.target.path)

    @export(property=True)
    def ips(self) -> list[str]:
        return []

    @export
    def users(self) -> Iterator[record.WindowsUserRecord]:
        yield record.WindowsUserRecord(
            sid="S-1-0-0",
            name=self.hostname,
            home=f"sysvol/users/{self.hostname}",
            _target=self.target,
        )

    @export(property=True)
    def os(self) -> str:
        return "windows"
