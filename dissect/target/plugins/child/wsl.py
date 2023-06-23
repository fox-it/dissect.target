import re
from pathlib import Path
from typing import Iterator

from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin
from dissect.target.plugins.general.users import UsersPlugin
from dissect.target.target import Target


def find_wsl_installs(target: Target) -> Iterator[Path]:
    """Function finds WSL distributions based off the locations stored in subkeys in the Windows Registry.
    # It is possible to have WSL disk files of perfectly working (custom imported) distributions anywhere on the filesystem ...
    # ... which is why the registry is used to locate their disk files. See:
    # https://learn.microsoft.com/en-us/windows/wsl/use-custom-distro
    # https://learn.microsoft.com/en-us/windows/wsl/enterprise
    """

    # Iterates the registry key generator objects to eventually get the BasePath of WSL distribution registry keys.
    def recursive_registry(generatorKey, subpath):
        for subkey in generatorKey:
            key_name = subkey.name
            next_generator = subkey
            if key_name == subpath[0]:
                if (subkeys := next_generator.subkeys()) is not None:
                    if len(subpath) > 1:
                        yield from recursive_registry(subkeys, subpath[1:])
                    else:  # This means the current registry generator object is the Lxss key.
                        for distribution_GUID in subkey.subkeys():
                            if re.match(
                                r"\{.*\}", distribution_GUID.name
                            ):  # Filters out subkeys that aren't distribution keys, such as AppxInstallerCache.
                                yield distribution_GUID.value(
                                    "BasePath"
                                ).value  # Location of the disk file is stored in BasePath value.

    # Uses the recursive_registry key function to get WSL distributions for all users.
    all_user_sids = [user_details.user.sid for user_details in UsersPlugin(target).all()]
    for user_sid in all_user_sids:
        user_wsl_key = ("HKEY_USERS/" + str(user_sid) + "/Software/Microsoft/Windows/CurrentVersion/Lxss").split("/")
        for wsl_install in recursive_registry(target.registry.keys("HKU"), user_wsl_key):
            wsl_install = str(Path(wsl_install)).replace(
                "\\\\?\\", ""
            )  # Dissect currently doesn't normalize \\?\, so the replace is a temporary solution.
            for disk_path in target.fs.path(wsl_install).glob(
                "*.vhdx"
            ):  # WSL does not work when the filename is not ext4.vhdx, but it is possible to change disk names when not using WSL.
                if (vhdx := target.fs.path(target.resolve(str(disk_path)))).exists():
                    yield vhdx


class WSLChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields WSL VHDX file locations.

    Windows WSL VHDX disk file locations are stored in the Windows Registry in `HKEY_USERS/$sid/Software/Microsoft/Windows/CurrentVersion/Lxss`,
    where $sid is substituted with any SID of users on the Windows machine.

    References:
        - https://www.osdfcon.org/presentations/2020/Asif-Matadar_Investigating-WSL-Endpoints.pdf
        - https://www.sans.org/white-papers/39330/
        - https://learn.microsoft.com/en-us/windows/wsl/disk-space#how-to-locate-the-vhdx-file-and-disk-path-for-your-linux-distribution
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
