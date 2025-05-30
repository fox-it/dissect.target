from __future__ import annotations

import io
import urllib.parse
from collections import defaultdict
from typing import TYPE_CHECKING, ClassVar
from unittest.mock import MagicMock, Mock, PropertyMock, call, patch

import pytest

from dissect.target import loader
from dissect.target.containers.raw import RawContainer
from dissect.target.exceptions import FilesystemError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.loaders.dir import DirLoader
from dissect.target.loaders.raw import RawLoader
from dissect.target.loaders.vbox import VBoxLoader
from dissect.target.target import DiskCollection, Event, Target, TargetLogAdapter, log

if TYPE_CHECKING:
    from collections.abc import Iterator
    from logging import Logger
    from pathlib import Path


class ErrorCounter(TargetLogAdapter):
    errors = 0

    def error(*args, **kwargs) -> None:
        ErrorCounter.errors += 1


@pytest.mark.parametrize(
    ("topo", "entry_point", "expected_result", "expected_errors"),
    [
        # Base cases:
        # Scenario 0:  Can we still load a single target that's not a dir?
        (
            [
                "/raw.tst",
            ],
            "/raw.tst",
            "[TestLoader('/raw.tst')]",
            0,
        ),
        # Scenario 0b: Make sure we still get so see errors if a target fails to load
        # (1 error + 1 exception no load)
        (
            [
                "/raw.vbox",
            ],
            "/raw.vbox",
            "[]",
            2,
        ),
        # Scenario 0c: Attempting to load a dir with nothing of interest yield an error
        # (1 exception no load)
        (
            [
                "/dir/garbage",
            ],
            "/dir",
            "[]",
            1,
        ),
        # Dir cases:
        # Scenario 1:  Dir is loadable target (simple)
        (
            [
                "/dir/etc",
                "/dir/var",
            ],
            "/dir",
            "[DirLoader('/dir')]",
            0,
        ),
        # Scenario 2: dir contains multiple loadable targets
        (
            [
                "/dir/raw.img",
                "/dir/raw2.tst",
            ],
            "/dir",
            "[RawLoader('/dir/raw.img'), TestLoader('/dir/raw2.tst')]",
            0,
        ),
        # Scenario 2b: dir contains multiple loadable targets and some garbage
        # (it will wrap the garbage in a RawLoader to try)
        (
            [
                "/dir/raw.img",
                "/dir/raw2.tst",
                "/dir/info.txt",
            ],
            "/dir",
            "[RawLoader('/dir/raw.img'), TestLoader('/dir/raw2.tst'), RawLoader('/dir/info.txt')]",
            0,
        ),
        # Scenario 3: dir contains 1 loadable dir as well as 2 loadable targets
        (
            [
                "/dir/unix/etc",
                "/dir/unix/var",
                "/dir/raw.img",
                "/dir/raw2.tst",
            ],
            "/dir",
            "[DirLoader('/dir/unix'), RawLoader('/dir/raw.img'), TestLoader('/dir/raw2.tst')]",
            0,
        ),
        # Scenario 3b: dir contains 2 loadable dirs as well as 2 loadable targets
        (
            [
                "/dir/unix/etc",
                "/dir/unix/var",
                "/dir/win/c:",
                "/dir/win/c:/windows/system32",
                "/dir/raw.img",
                "/dir/raw2.tst",
            ],
            "/dir",
            "[DirLoader('/dir/unix'), DirLoader('/dir/win'), RawLoader('/dir/raw.img'), TestLoader('/dir/raw2.tst')]",
            0,
        ),
        # Scenario 4: dir is a loadable dir but contains other files including loadable targets
        (
            [
                "/dir/etc",
                "/dir/var",
                "/dir/raw.img",
                "/dir/info.txt",
            ],
            "/dir",
            "[DirLoader('/dir')]",
            0,
        ),
        # Scenario 4b: Windows variant
        (
            [
                "/dir/c:",
                "/dir/c:/windows/system32",
                "/dir/raw.img",
                "/dir/info.txt",
            ],
            "/dir",
            "[DirLoader('/dir')]",
            0,
        ),
        # Scenario 5: Hypothetical Dirloader with selection
        (
            [
                "/dir/select.txt",  # selects 1 and 3
                "/dir/raw1.img",
                "/dir/raw2.img",
                "/dir/raw3.img",
            ],
            "/dir",
            "[SelectLdr('/dir/raw1.img'), SelectLdr('/dir/raw3.img')]",
            0,
        ),
    ],
)
@patch("dissect.target.target.getlogger", new=lambda t: ErrorCounter(log, {"target": t}))
def test_target_open_dirs(topo: list[str], entry_point: str, expected_result: str, expected_errors: int) -> None:
    # TestLoader to mix Raw Targets with Test Targets without depending on
    # specific implementations.
    class TestLoader(RawLoader):
        @staticmethod
        def detect(path: Path) -> bool:
            return str(path).endswith(".tst")

        def map(self, target: Target) -> None:
            target.disks.add(RawContainer(io.BytesIO(b"\x00")))

    class SelectLdr(DirLoader):
        @staticmethod
        def detect(path: Path) -> bool:
            return path.is_dir() and path.joinpath("select.txt").exists()

        @staticmethod
        def find_all(path: Path, **kwargs) -> Iterator[Path]:
            return [path.joinpath("/dir/raw1.img"), path.joinpath("/dir/raw3.img")]

        def map(self, target: Target) -> None:
            target.disks.add(RawContainer(io.BytesIO(b"\x00")))

    def make_vfs(topo: dict) -> dict:
        vfs = VirtualFilesystem()
        for entry in topo:
            if entry.find(".") > -1:
                vfs.map_file_fh(entry, io.BytesIO(b"\x00"))
            else:
                vfs.makedirs(entry)
        return vfs

    def dirtest(vfs: dict, selector: str) -> list:
        ErrorCounter.errors = 0
        try:
            return [x._loader for x in Target.open_all([vfs.path(selector)])]
        except Exception:
            ErrorCounter.errors += 1
            return []

    with patch.object(loader, "LOADERS", [VBoxLoader, TestLoader, SelectLdr]):
        assert str(dirtest(make_vfs(topo), entry_point)) == expected_result

        assert ErrorCounter.errors == expected_errors


@pytest.fixture
def mocked_win_volumes_fs() -> Iterator[tuple[Mock, Mock, Mock]]:
    mock_bad_volume = Mock(name="bad-volume-Z")
    mock_bad_volume.fs = None
    mock_bad_volume.drive_letter = "Z"

    mock_good_volume = Mock(name="good-volume-W")
    mock_good_volume.fs = None
    mock_good_volume.drive_letter = "W"

    mock_good_fs = Mock(name="good-fs")
    mock_good_fs.iter_subfs.return_value = []

    def mock_filesystem_open(volume: Mock) -> Mock:
        if volume == mock_good_volume:
            return mock_good_fs
        raise FilesystemError("Not supported")

    def get_mock_drive_volumes(log: Logger) -> list[tuple[Mock, bool, Mock, int]]:
        # drive_volume, is_windrive, disk, disk_num
        return [
            (mock_good_volume, False, Mock(), 1),
            (mock_bad_volume, False, Mock(), 2),
        ]

    def mock_disk_apply(self: DiskCollection) -> None:
        if len(self.target.disks) > 0:
            self.target.volumes.add(mock_good_volume)
            self.target.volumes.add(mock_bad_volume)

    with (
        patch("dissect.target.loaders.local._get_os_name") as mock_os_name,
        patch("dissect.target.filesystem.open", new=mock_filesystem_open),
        patch("dissect.target.plugin.os_plugins") as mock_os_plugins,
        patch("dissect.target.target.DiskCollection.apply", new=mock_disk_apply),
        patch("dissect.target.loaders.local._get_windows_drive_volumes", new=get_mock_drive_volumes),
    ):
        mock_os_plugins.return_value = []
        mock_os_name.return_value = "windows"

        yield (mock_good_volume, mock_bad_volume, mock_good_fs)


@pytest.fixture
def mocked_lin_volumes_fs() -> Iterator[tuple[Mock, Mock, Mock]]:
    mock_bad_volume = Mock(name="bad-volume")
    mock_bad_volume.fs = None

    mock_good_volume = Mock(name="good-volume")
    mock_good_volume.fs = None

    mock_good_fs = Mock(name="good-fs")

    def mock_filesystem_open(volume: Mock) -> Mock:
        if volume == mock_good_volume:
            return mock_good_fs
        raise FilesystemError("Not supported")

    def mock_disk_apply(self: DiskCollection) -> None:
        if len(self.target.disks) > 0:
            self.target.volumes.add(mock_good_volume)
            self.target.volumes.add(mock_bad_volume)

    with (
        patch("dissect.target.loaders.local._get_os_name") as mock_os_name,
        patch("dissect.target.filesystem.open", new=mock_filesystem_open),
        patch("dissect.target.plugin.os_plugins") as mock_os_plugins,
        patch("dissect.target.target.DiskCollection.apply", new=mock_disk_apply),
    ):
        mock_os_plugins.return_value = []
        mock_os_name.return_value = "linux"

        yield (mock_good_volume, mock_bad_volume, mock_good_fs)


def test_target_win_force_dirfs(mocked_win_volumes_fs: tuple[Mock, Mock, Mock]) -> None:
    mock_good_volume, mock_bad_volume, mock_good_fs = mocked_win_volumes_fs

    query = {"force-directory-fs": 1}
    target_query = urllib.parse.urlencode(query)
    force_dirfs_path = f"local?{target_query}"
    target = Target.open(force_dirfs_path)

    assert "force-directory-fs" in target.path_query

    # original volumes are attached
    assert len(target.volumes) == 2

    # FSs from both volumes, bad and good, are mounted + 2 mounts by DefaultOSPlugin
    assert set(target.fs.mounts.keys()) == {
        mock_bad_volume.drive_letter,
        mock_good_volume.drive_letter,
        "fs0",
        "fs1",
    }

    # both volumes should be mounted as DirectoryFilesystem
    assert isinstance(target.fs.mounts[mock_good_volume.drive_letter], DirectoryFilesystem)
    assert isinstance(target.fs.mounts[mock_bad_volume.drive_letter], DirectoryFilesystem)


def test_target_win_fallback_dirfs(mocked_win_volumes_fs: tuple[Mock, Mock, Mock]) -> None:
    mock_good_volume, mock_bad_volume, mock_good_fs = mocked_win_volumes_fs

    query = {"fallback-to-directory-fs": 1}
    target_query = urllib.parse.urlencode(query)
    fallback_dirfs_path = f"local?{target_query}"
    target = Target.open(fallback_dirfs_path)

    assert "fallback-to-directory-fs" in target.path_query

    # both volumes are present
    assert len(target.volumes) == 2

    # FSs from both volumes, bad and good, are mounted + 2 mounts by DefaultOSPlugin
    assert set(target.fs.mounts.keys()) == {
        mock_bad_volume.drive_letter,
        mock_good_volume.drive_letter,
        "fs0",
        "fs1",
    }

    # One volume is mounted as DirectoryFilesystem, another as original mock_good_fs
    assert target.fs.mounts[mock_good_volume.drive_letter] == mock_good_fs
    assert isinstance(target.fs.mounts[mock_bad_volume.drive_letter], DirectoryFilesystem)


def test_target_force_dirfs_linux(mocked_lin_volumes_fs: tuple[Mock, Mock, Mock]) -> None:
    query = {"force-directory-fs": 1}
    target_query = urllib.parse.urlencode(query)
    force_dirfs_path = f"local?{target_query}"
    target = Target.open(force_dirfs_path)

    assert "force-directory-fs" in target.path_query

    # no original volumes should be attached
    assert len(target.volumes) == 0

    assert len(target.fs.mounts) == 1
    assert target.fs.mounts.get("/")
    assert isinstance(target.fs.mounts["/"], DirectoryFilesystem)


def test_target_fallback_dirfs_linux(mocked_lin_volumes_fs: tuple[Mock, Mock, Mock]) -> None:
    query = {"fallback-to-directory-fs": 1}
    target_query = urllib.parse.urlencode(query)
    fallback_dirfs_path = f"local?{target_query}"
    target = Target.open(fallback_dirfs_path)

    assert "fallback-to-directory-fs" in target.path_query

    # no volumes should be attached, since no disks were attached
    # see comment in LocalLoader.map() for more info
    assert len(target.volumes) == 0

    assert len(target.fs.mounts) == 1
    assert target.fs.mounts.get("/")
    assert isinstance(target.fs.mounts["/"], DirectoryFilesystem)


def test_target__generic_name_no_path_no_os() -> None:
    target_bare = Target()

    assert target_bare._generic_name == "Unknown"


def test_target__generic_name_no_path_with_os() -> None:
    target_bare = Target()
    target_bare.os = "test"

    assert target_bare._generic_name == "Unknown-test"


def test_target__generic_name_with_path(target_bare: Target) -> None:
    assert target_bare._generic_name == target_bare.path.name


def test_target_name_no_hostname() -> None:
    test_name = "test-target"

    with patch("dissect.target.target.Target._generic_name", PropertyMock(return_value=test_name)):
        target_bare = Target()
        target_bare.hostname = None

        assert target_bare.name == test_name


def test_target_name_hostname_raises() -> None:
    test_name = "test-target"

    with (
        patch("dissect.target.target.Target._generic_name", PropertyMock(return_value=test_name)),
        patch("dissect.target.target.Target.hostname", PropertyMock(side_effect=Exception("ERROR")), create=True),
    ):
        target_bare = Target()

        assert target_bare.name == test_name


def test_target_name_set() -> None:
    test_name = "test-target"
    target_bare = Target()
    target_bare._name = test_name

    assert target_bare.name == test_name


def test_target_name_target_applied() -> None:
    test_name = "test-target"

    with patch("dissect.target.target.Target._generic_name", PropertyMock(return_value=test_name)):
        target_bare = Target()
        target_bare.hostname = None
        target_bare._applied = True

        assert target_bare.name == test_name
        assert target_bare._name == test_name


def test_target_set_event_callback() -> None:
    mock_callback1 = MagicMock()
    mock_callback2 = MagicMock()

    class MockTarget(Target):
        event_callbacks: ClassVar = defaultdict(set)

    MockTarget.set_event_callback(event_type=None, event_callback=mock_callback1)
    MockTarget.set_event_callback(event_type=None, event_callback=mock_callback2)
    MockTarget.set_event_callback(event_type=Event.FUNC_EXEC, event_callback=mock_callback1)
    MockTarget.set_event_callback(event_type=Event.FUNC_EXEC, event_callback=mock_callback2)

    assert hasattr(MockTarget, "event_callbacks")

    event_callbacks = MockTarget.event_callbacks

    assert None in event_callbacks
    assert Event.FUNC_EXEC in event_callbacks

    assert len(event_callbacks[None]) == 2
    assert len(event_callbacks[Event.FUNC_EXEC]) == 2

    assert mock_callback1 in event_callbacks[None]
    assert mock_callback2 in event_callbacks[None]
    assert mock_callback1 in event_callbacks[Event.FUNC_EXEC]
    assert mock_callback2 in event_callbacks[Event.FUNC_EXEC]


def test_target_send_event() -> None:
    mock_callback1 = MagicMock()
    mock_callback2 = MagicMock()

    class MockTarget(Target):
        event_callbacks: ClassVar = defaultdict(set)

    MockTarget.set_event_callback(event_type=None, event_callback=mock_callback1)
    MockTarget.set_event_callback(event_type=Event.FUNC_EXEC, event_callback=mock_callback2)

    target_bare = MockTarget()
    target_bare.send_event(None, test="None")
    target_bare.send_event(Event.FUNC_EXEC, test="FUNC_EXEC")

    calls = [
        call(target_bare, None, test="None"),
        call(target_bare, Event.FUNC_EXEC, test="FUNC_EXEC"),
    ]
    mock_callback1.assert_has_calls(calls)
    mock_callback2.assert_called_once_with(target_bare, Event.FUNC_EXEC, test="FUNC_EXEC")


def test_empty_vs(target_bare: Target) -> None:
    mock_disk = MagicMock()
    mock_disk.vs = None

    mock_volume_system = MagicMock()
    mock_volume_system.volumes = []

    target_bare.disks.add(mock_disk)

    with patch("dissect.target.volume.open") as volume_open:
        volume_open.return_value = mock_volume_system

        target_bare.disks.apply()

        assert len(target_bare.volumes) == 1
        assert target_bare.volumes[0].disk is mock_disk
        assert target_bare.volumes[0].offset == 0


def test_nested_vs(target_bare: Target) -> None:
    mock_base_volume = MagicMock()
    mock_base_volume.offset = 0
    mock_base_volume.vs = None
    mock_base_volume.fs = None
    target_bare.volumes.add(mock_base_volume)

    mock_volume = MagicMock()
    mock_volume.offset = 0
    mock_volume.vs.__type__ = "disk"
    mock_volume.fs = None

    mock_volume_system = MagicMock()
    mock_volume_system.volumes = [mock_volume]

    with patch("dissect.target.volume.open") as volume_open, patch("dissect.target.filesystem.open") as filesystem_open:
        volume_open.return_value = mock_volume_system

        target_bare.volumes.apply()
        filesystem_open.assert_has_calls([call(mock_base_volume), call(mock_volume)])
        assert len(target_bare.volumes) == 2
        assert len(target_bare.filesystems) == 2


def test_vs_offset_0(target_bare: Target) -> None:
    mock_disk = MagicMock()
    mock_disk.vs = None
    target_bare.disks.add(mock_disk)

    mock_volume = MagicMock()
    mock_volume.offset = 0
    mock_volume.vs.__type__ = "disk"
    mock_volume.fs = None

    mock_volume_system = MagicMock()
    mock_volume_system.volumes = [mock_volume]

    with patch("dissect.target.volume.open") as volume_open, patch("dissect.target.filesystem.open") as filesystem_open:
        volume_open.return_value = mock_volume_system

        target_bare.disks.apply()
        volume_open.assert_called_once_with(mock_disk)
        assert len(target_bare.volumes) == 1

        target_bare.volumes.apply()
        # volume.open must still only be called once
        volume_open.assert_called_once_with(mock_disk)
        filesystem_open.assert_called_once_with(mock_volume)
        assert len(target_bare.volumes) == 1
        assert len(target_bare.filesystems) == 1


@pytest.mark.parametrize("nr_of_fs", [1, 2])
def test_fs_mount_others(target_unix: Target, nr_of_fs: int) -> None:
    for _ in range(nr_of_fs):
        target_unix.filesystems.add(Mock())

    target_unix._mount_others()

    for idx in range(nr_of_fs):
        assert f"/$fs$/fs{idx}" in target_unix.fs.mounts
        assert target_unix.fs.path(f"$fs$/fs{idx}").exists()

    assert not target_unix.fs.path(f"$fs$/fs{nr_of_fs}").exists()


@pytest.mark.parametrize("nr_of_fs", [1, 2])
def test_fs_mount_already_there(target_unix: Target, nr_of_fs: int) -> None:
    for idx in range(nr_of_fs):
        target_unix.filesystems.add(Mock())
        target_unix._mount_others()

        assert f"/$fs$/fs{idx}" in target_unix.fs.mounts
        assert target_unix.fs.path(f"$fs$/fs{idx}").exists()


def test_children_on_invalid_target(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    """Test that we don't attempt to load child targets on an invalid target."""
    p = tmp_path.joinpath("empty-dir")
    p.mkdir()

    mock_loader = Mock()
    mock_loader.find_all.return_value = [None]
    mock_loader.return_value = None

    with patch.object(loader, "find_loader", return_value=mock_loader):
        try:
            list(Target.open_all([p], include_children=True))
        except Exception:
            pass

    assert "Failed to load child target from None" not in caplog.text
