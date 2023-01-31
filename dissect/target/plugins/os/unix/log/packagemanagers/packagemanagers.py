from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.log.packagemanagers.model import (
    PackageManagerLogRecord,
)


class PackageManagerPlugin(Plugin):
    __namespace__ = "packagemanagers"
    TOOLS = [
        "apt",
        "yum",
        "zypper",
    ]

    def __init__(self, target: Target):
        super().__init__(target)
        self._plugins = []
        for entry in self.TOOLS:
            try:
                self._plugins.append(getattr(self.target, entry))
            except Exception:  # noqa
                target.log.exception(f"Failed to load tool plugin: {entry}")

    def check_compatible(self) -> bool:
        if not len(self._plugins):
            raise UnsupportedPluginError("No compatible plugins found")

    @export(record=PackageManagerLogRecord)
    def package_manager_logs(self):
        """Returns logs from apt, yum and zypper package managers."""
        for plugin in self._plugins:
            # running the logs function for each plugin
            getattr(plugin, "logs")()
