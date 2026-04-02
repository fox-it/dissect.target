from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pathlib

    from dissect.target.target import Target


def test_bloodhound(target_win_ntds: Target, tmp_path: pathlib.Path) -> None:
    """Tests if ``ad.bloodhound`` outputs the correct amount of records and their content."""
    target_win_ntds.bloodhound(tmp_path)
