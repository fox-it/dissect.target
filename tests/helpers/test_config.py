from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from dissect.target.helpers import config


def test_load_config() -> None:
    # FS layout:
    #
    # temp_dir1
    #   config_file
    #   symlink_dir2 -> ../temp_dir2
    # temp_dir2

    with TemporaryDirectory() as temp_dir1, TemporaryDirectory() as temp_dir2:
        # create symlink in temp_dir1 pointing to temp_dir2
        symlink = Path(temp_dir1).joinpath("symlink")
        symlink.symlink_to(temp_dir2)

        config_file = Path(temp_dir1).joinpath(config.CONFIG_NAME)
        config_file.write_text('CONFIG_FILE = "found"')

        result = config.load(symlink)
        assert result.CONFIG_FILE == "found"
