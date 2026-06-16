from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import RegistryValueNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.helpers.regutil import RegistryKey
    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target


StartupRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/startup",
    [
        ("datetime", "ts_mtime"),
        ("datetime", "ts_btime"),
        ("command", "command"),
        ("path", "source"),
    ],
)


class StartupPlugin(Plugin):
    """Windows startup plugin.

    Extracts entries from Windows Startup directories and registry folders. Location can be customized with registry key
    ``(HKLM|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\(Shell Folders|User Shell Folders)\\Startup``

    References:
        - https://support.microsoft.com/en-us/windows/configure-startup-applications-in-windows-115a420a-0bff-4a6f-90e0-1934c844e473
    """

    SYSTEM_PATH = "/sysvol/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/"
    USER_PATH = "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"

    SYSTEM_KEYS = (
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    )
    USER_KEYS = (
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.startup_files = set(self.find_startup_files())

    def find_startup_files(self) -> Iterator[tuple[Path, UserDetails | None, RegistryKey | None]]:
        """Yields found configured startup files which may or may not exist on the target."""

        seen = set()

        for path in self.target.fs.path(self.SYSTEM_PATH).glob("*"):
            if path.is_file() and path.name != "desktop.ini":
                seen.add(path)
                yield path, None, None

        for user_details in self.target.user_details.all_with_home():
            for path in user_details.home_path.joinpath(self.USER_PATH).glob("*"):
                if path.is_file() and path.name != "desktop.ini":
                    seen.add(path)
                    yield path, user_details, None

        # The ``Shell Folders\\Startup`` and ``User Shell Folders\\Startup`` can point towards an alternative folder
        # with files, or to a specific file.
        if self.target.has_function("registry"):
            for key_path in self.SYSTEM_KEYS + self.USER_KEYS:
                for key in self.target.registry.keys(key_path):
                    user_details = self.target.registry.get_user_details(key)

                    for name in ("Startup", "Common Startup"):
                        try:
                            value: str = key.value(name).value
                        except RegistryValueNotFoundError:
                            continue

                        path: Path = self.target.resolve(value, user_details.user.sid if user_details else None)  # type: ignore
                        if path in seen:
                            continue

                        # Yield if the path does not exist (could be dir or file leftover artifact, we don't know).
                        # We also yield if the path is a file.
                        if not path.exists() or path.is_file():
                            # Some values can not be resolved by the resolver plugin.
                            if value.endswith("Microsoft\\Windows\\Start Menu\\Programs\\Startup"):
                                continue
                            seen.add(path)
                            yield path, user_details, key

                        if path.is_dir():
                            for child in path.glob("*"):
                                if child.name == "desktop.ini" or child in seen:
                                    continue
                                seen.add(child)
                                yield child, user_details, key

    def check_compatible(self) -> None:
        if not self.startup_files:
            raise UnsupportedPluginError("No Startup files found on target")

    @export(record=StartupRecord)
    def startup(self) -> Iterator[StartupRecord]:
        """Return the contents of Startup folders."""

        for file_path, user_details, reg_key in self.startup_files:
            source = None
            ts_mtime = None
            ts_btime = None

            if file_path.exists():
                stat = file_path.lstat()
                ts_mtime = stat.st_mtime
                ts_btime = getattr(stat, "st_birthtime", None)
                source = file_path.parent.resolve()

            elif reg_key:
                ts_mtime = reg_key.ts
                source = f"{self.target.registry.get_hive_shortname(reg_key)}\\{reg_key.path}"

            yield StartupRecord(
                ts_mtime=ts_mtime,
                ts_btime=ts_btime,
                command=f"'{file_path.resolve()}'",
                source=source,
                _user=user_details.user if user_details else None,
                _target=self.target,
            )
