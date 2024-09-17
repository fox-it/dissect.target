from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystems.squashfs import SquashFSFilesystem
from dissect.target.helpers import configutil
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import UnixApplicationRecord
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target


class SnapPlugin(Plugin):
    """Canonical Linux Snapcraft plugin.

    Reads information from installed ``*.snap`` files found in ``/var/lib/snapd/snaps``.
    Logs of the ``snapd`` daemon can be parsed using the ``journal`` or ``syslog`` plugins.

    Resources:
        - https://github.com/canonical/snapcraft
        - https://en.wikipedia.org/wiki/Snap_(software)
    """

    PATHS = [
        "/var/lib/snapd/snaps",
    ]

    def __init__(self, target: Target):
        super().__init__(target)
        self.installs = list(self._find_installs())

    def check_compatible(self) -> None:
        if not configutil.HAS_YAML:
            raise UnsupportedPluginError("Missing required dependency ruamel.yaml")

        if not self.installs:
            raise UnsupportedPluginError("No snapd install folder(s) found")

    def _find_installs(self) -> Iterator[TargetPath]:
        for str_path in self.PATHS:
            if (path := self.target.fs.path(str_path)).exists():
                yield path

    @export(record=UnixApplicationRecord)
    def snap(self) -> Iterator[UnixApplicationRecord]:
        """Yield installed snap packages."""

        for install_path in self.installs:
            for snap in install_path.glob("*.snap"):
                try:
                    squashfs = SquashFSFilesystem(snap.open())

                except (ValueError, NotImplementedError) as e:
                    self.target.log.warning("Unable to open snap file %s", snap)
                    self.target.log.debug("", exc_info=e)
                    continue

                if not (meta := squashfs.path("meta/snap.yaml")).exists():
                    self.target.log.warning("Snap %s has no meta/snap.yaml file")
                    continue

                meta_data = configutil.parse(meta, hint="yaml")

                yield UnixApplicationRecord(
                    ts_modified=meta.lstat().st_mtime,
                    name=meta_data.get("name"),
                    version=meta_data.get("version"),
                    path=snap,
                    _target=self.target,
                )
