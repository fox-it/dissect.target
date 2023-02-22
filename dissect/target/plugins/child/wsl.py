from pathlib import Path
from typing import Iterator

from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin
from dissect.target.target import Target


def find_wsl_installs(target: Target) -> Iterator[Path]:
    # Officially supported distro's by Microsoft can be found under "PackageFamilyName" at
    # https://github.com/microsoft/WSL/blob/master/distributions/DistributionInfo.json

    dist_folders = [
        "CanonicalGroupLimited.Ubuntu*",
        "TheDebianProject.DebianGNULinux_*",
        "KaliLinux.*",
        "*SUSE.openSUSE*",
        "*OracleAmericaInc.OracleLinux*",
    ]

    for user_details in target.user_details.all_with_home():
        for dist_folder in dist_folders:
            for install_path in user_details.home_path.joinpath("AppData/Local/Packages").glob(dist_folder):
                if (vhdx := install_path.joinpath("LocalState/ext4.vhdx")).exists():
                    yield vhdx


class WSLChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields WSL VHDX file locations.

    Windows WSL VHDX conatiners are stored at ``%AppData%\\Local\\Packages\\$DistFolder\\LocalState\\ext4.vhdx``,
    where ``$DistFolder`` will be substituted with a unix distribution folder.

    Sources:
        - https://www.osdfcon.org/presentations/2020/Asif-Matadar_Investigating-WSL-Endpoints.pdf
        - https://www.sans.org/white-papers/39330/
    """  # noqa: E501

    __type__ = "wsl"

    def __init__(self, target: Target):
        super().__init__(target)
        self.installs = list(find_wsl_installs(target))

    def check_compatible(self) -> bool:
        return len(self.installs) > 0

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for install_path in self.installs:
            yield ChildTargetRecord(
                type=self.__type__,
                path=install_path,
                _target=self.target,
            )
