from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows.jumplist import JumpListPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_os_windows_jumplist(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    custom_destination = absolute_path("_data/plugins/os/windows/jumplist/590aee7bdd69b59b.customDestinations-ms")
    automatic_destination = absolute_path("_data/plugins/os/windows/jumplist/5f7b5f1e01b83767.automaticDestinations-ms")

    user_details = target_win_users.user_details.find(username="John")

    fs_win.map_file(
        str(
            user_details.home_path.joinpath(
                "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/590aee7bdd69b59b.customDestinations-ms"
            )
        )[3:],  # drop C:/
        custom_destination,
    )
    fs_win.map_file(
        str(
            user_details.home_path.joinpath(
                "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/5f7b5f1e01b83767.automaticDestinations-ms"
            )
        )[3:],  # drop C:/
        automatic_destination,
    )

    target_win_users.add_plugin(JumpListPlugin)

    records = list(target_win_users.jumplist())
    assert len(records) == 3

    record = records[0]
    assert record.application_id == "590aee7bdd69b59b"
    assert record.application_name == "Powershell Windows 10"
    assert record.type == "customDestinations"
