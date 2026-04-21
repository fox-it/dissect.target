from __future__ import annotations

import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.locale import macOSLocalePlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            (
                ".GlobalPreferences.plist",
                ".AppleSetupDone",
                "com.apple.timezone.auto.plist",
            ),
            (
                "/Library/Preferences/.GlobalPreferences.plist",
                "/private/var/db/.AppleSetupDone",
                "/Library/Preferences/com.apple.timezone.auto.plist",
            ),
        ),
    ],
)
def test_locale(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    tz = timezone.utc
    apple_setup_time = 1704067199

    tmpdir = tempfile.mkdtemp()
    try:
        for name, path in zip(names, paths, strict=True):
            if name == ".AppleSetupDone":
                src = absolute_path("_data/plugins/os/unix/bsd/darwin/macos/locale/.AppleSetupDone")

                tmp_file = os.path.join(tmpdir, name)  # noqa: PTH118
                shutil.copyfile(src, tmp_file)

                os.utime(tmp_file, (apple_setup_time, apple_setup_time))
            else:
                tmp_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/locale/{name}")

            fs_unix.map_file(path, tmp_file)

        target_unix.fs.mount("/", fs_unix)
        target_unix.os = "macos"
        target_unix.add_plugin(macOSLocalePlugin)

        assert target_unix.timezone == "Europe/Amsterdam"
        assert target_unix.language == ["en_US", "nl_NL"]
        assert target_unix.install_date == datetime.fromtimestamp(apple_setup_time, tz=tz)
        assert target_unix.location_services_active

    finally:
        target_unix.fs = None
        os.system(f'rmdir /s /q "{tmpdir}"' if os.name == "nt" else f'rm -rf "{tmpdir}"')
