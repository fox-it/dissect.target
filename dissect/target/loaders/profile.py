from pathlib import Path

from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.helpers.record import WindowsUserRecord
from dissect.target.loader import Loader
from dissect.target.plugin import OSPlugin, export
from dissect.target.plugins.os.windows.registry import RegistryPlugin


class ProfileLoader(Loader):
    """Load NTUSER.DAT files."""

    def __init__(self, path, **kwargs):
        path = Path(path).resolve()
        super().__init__(path)

    @staticmethod
    def detect(path):
        if path.is_dir() and path.joinpath("NTUSER.DAT").exists():
            return True

        return False

    def map(self, target):
        username = self.path.name

        dfs = DirectoryFilesystem(self.path, case_sensitive=False)
        target.filesystems.add(dfs)
        target.fs.mount(f"sysvol/users/{username}", dfs)

        target._os_plugin = ProfileOSPlugin
        target.add_plugin(RegistryPlugin, check_compatible=False)


class ProfileOSPlugin(OSPlugin):
    @classmethod
    def detect(cls, target):
        return True

    @classmethod
    def create(cls, target, sysvol):
        return cls(target)

    @export(property=True)
    def hostname(self):
        return self.target._generic_name

    @export(property=True)
    def ips(self):
        return []

    @export(property=True)
    def version(self):
        return None

    @export
    def users(self):
        yield WindowsUserRecord(
            sid="0",
            name=self.hostname,
            home=f"sysvol/users/{self.hostname}",
            _target=self.target,
        )

    @export(property=True)
    def os(self):
        return "windows"
