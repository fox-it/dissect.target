from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import PluginError, UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target


def find_wsl_installs(target: Target) -> Iterator[Path]:
    """Find all WSL disk files.

    Disk files for working (custom) Linux distributions can be located anywhere on the system.
    Locations to disk files for each user's WSL instance is stored in the Windows registry at
    ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss``.

    References:
        - https://learn.microsoft.com/en-us/windows/wsl/use-custom-distro
        - https://learn.microsoft.com/en-us/windows/wsl/enterprise
    """

    try:
        for lxss_key in target.registry.keys("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"):
            for distribution_key in lxss_key.subkeys():
                if not distribution_key.name.startswith("{"):
                    continue
                base_path = target.resolve(distribution_key.value("BasePath").value)
                # WSL needs diskname to be ext4.vhdx, but they can be renamed when WSL is not active
                yield from base_path.glob("*.vhdx")
    except PluginError:
        pass


class WSLChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields WSL VHDX file locations.

    Windows WSL VHDX disk file locations are stored in the Windows registry in ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss``.

    References:
        - https://www.osdfcon.org/presentations/2020/Asif-Matadar_Investigating-WSL-Endpoints.pdf
        - https://www.sans.org/white-papers/39330/
        - https://learn.microsoft.com/en-us/windows/wsl/disk-space#how-to-locate-the-vhdx-file-and-disk-path-for-your-linux-distribution
    """  # noqa: E501

    __type__ = "wsl"

    def __init__(self, target: Target):
        super().__init__(target)
        self.installs = list(find_wsl_installs(target))

    def check_compatible(self) -> None:
        if not len(self.installs):
            raise UnsupportedPluginError("No WSL installs found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for install_path in self.installs:
            yield ChildTargetRecord(
                type=self.__type__,
                path=install_path,
                _target=self.target,
            )
