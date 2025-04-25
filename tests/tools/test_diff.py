from __future__ import annotations

import textwrap
from io import BytesIO, StringIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.fsutil import stat_result
from dissect.target.tools import fsutils
from dissect.target.tools.diff import (
    DifferentialCli,
    TargetComparison,
    differentiate_target_filesystems,
    differentiate_target_plugin_outputs,
    likely_unchanged,
)
from dissect.target.tools.diff import main as target_diff
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target
    from tests.conftest import TargetUnixFactory

PASSWD_CONTENTS = """
            root:x:0:0:root:/root:/bin/bash
            user:x:1000:1000:user:/home/user:/bin/bash
            """


@pytest.fixture
def src_target(target_unix_factory: TargetUnixFactory) -> Target:
    target, fs_unix = target_unix_factory.new("src_target")

    passwd_contents = PASSWD_CONTENTS + "\nsrc_user:x:1001:1001:src_user:/home/src_user:/bin/bash"

    fs_unix.map_file_fh("/etc/passwd", BytesIO(textwrap.dedent(passwd_contents).encode()))

    fs_unix.map_file_fh("changes/unchanged", BytesIO(b"Unchanged"))
    fs_unix.map_file_fh("changes/changed", BytesIO(b"Hello From Source Target"))
    fs_unix.map_file_fh("changes/only_on_src", BytesIO(b"FooBarBaz"))

    fs_unix.map_file_fh("changes/subdirectory_both/on_both", BytesIO(b"On Both"))
    fs_unix.map_file_fh("changes/subdirectory_src/only_on_src", BytesIO(b"Hello From Source Target"))

    fs_unix.map_file_fh("changes/file_on_src", BytesIO(b"Hello From Source Target"))
    fs_unix.map_file_fh("changes/dir_on_src/file", BytesIO(b"Hello From Source Target"))
    return target


@pytest.fixture
def dst_target(target_unix_factory: TargetUnixFactory) -> Target:
    target, fs_unix = target_unix_factory.new("dst_target")

    passwd_contents = PASSWD_CONTENTS + "\ndst_user:x:1002:1002:dst_user:/home/dst_user:/bin/bash"

    fs_unix.map_file_fh("/etc/passwd", BytesIO(textwrap.dedent(passwd_contents).encode()))

    fs_unix.map_file_fh("changes/unchanged", BytesIO(b"Unchanged"))
    fs_unix.map_file_fh("changes/changed", BytesIO(b"Hello From Destination Target"))
    fs_unix.map_file_fh("changes/only_on_dst", BytesIO(b"BazBarFoo"))

    fs_unix.map_file_fh("changes/subdirectory_both/on_both", BytesIO(b"On Both"))
    fs_unix.map_file_fh("changes/subdirectory_dst/only_on_dst", BytesIO(b"Hello From Destination Target"))

    fs_unix.map_file_fh("changes/dir_on_src", BytesIO(b"Hello From Destination Target"))
    fs_unix.map_file_fh("changes/file_on_src/file", BytesIO(b"Hello From Destination Target"))
    return target


def test_scandir(src_target: Target, dst_target: Target) -> None:
    comparison = TargetComparison(src_target, dst_target, deep=True)
    diff = comparison.scandir("changes")

    assert len(diff.deleted) == 4
    assert diff.deleted[0].name == "only_on_src"
    assert diff.deleted[0].open().read() == b"FooBarBaz"
    assert diff.deleted[1].name == "subdirectory_src"
    assert diff.deleted[2].name == "dir_on_src"
    assert diff.deleted[3].open().read() == b"Hello From Source Target"

    assert len(diff.created) == 4
    assert diff.created[0].open().read() == b"BazBarFoo"
    assert diff.created[0].name == "only_on_dst"
    assert diff.created[1].name == "subdirectory_dst"

    assert diff.created[2].name == "dir_on_src"
    assert diff.created[2].open().read() == b"Hello From Destination Target"
    assert diff.created[3].name == "file_on_src"
    assert diff.created[3].is_dir()

    assert len(diff.unchanged) == 2
    assert diff.unchanged[0].open().read() == b"Unchanged"
    assert diff.unchanged[0].name == "unchanged"

    assert diff.unchanged[1].name == "subdirectory_both"

    assert len(diff.modified) == 1
    differential_entry = diff.modified[0]
    assert differential_entry.src_target_entry.open().read() == b"Hello From Source Target"
    assert differential_entry.dst_target_entry.open().read() == b"Hello From Destination Target"
    assert differential_entry.diff == [
        b"--- \n",
        b"+++ \n",
        b"@@ -1 +1 @@\n",
        b"-Hello From Source Target",
        b"+Hello From Destination Target",
    ]


def test_walkdir(src_target: Target, dst_target: Target) -> None:
    comparison = TargetComparison(src_target, dst_target, deep=True)
    differentials = list(comparison.walkdir("changes"))

    assert len(differentials) == 6
    assert sorted(differential.directory for differential in differentials) == [
        "/changes/dir_on_src",
        "/changes/file_on_src",
        "/changes/subdirectory_both",
        "/changes/subdirectory_dst",
        "/changes/subdirectory_src",
        "changes",
    ]

    assert differentials[0].directory == "changes"

    subdirectories_only_on_dst = ["/changes/subdirectory_dst", "/changes/file_on_src"]
    for subdirectory in subdirectories_only_on_dst:
        differential = next(differential for differential in differentials if differential.directory == subdirectory)

        # All entries should be 'created' as this directory doesn't exist on the source target
        assert len(differential.modified) == 0
        assert len(differential.deleted) == 0
        assert len(differential.unchanged) == 0
        assert len(differential.created) == 1
        assert differential.created[0].open().read() == b"Hello From Destination Target"

    subdirectories_only_on_src = ["/changes/subdirectory_src", "/changes/dir_on_src"]

    for subdirectory in subdirectories_only_on_src:
        differential = next(differential for differential in differentials if differential.directory == subdirectory)

        # All entries should be 'created' as this directory doesn't exist on the destination target
        assert len(differential.modified) == 0
        assert len(differential.deleted) == 1
        assert len(differential.unchanged) == 0
        assert len(differential.created) == 0
        assert differential.deleted[0].open().read() == b"Hello From Source Target"

    # All entries should be 'unchanged' as this folder is identical on both
    assert len(differentials[3].modified) == 0
    assert len(differentials[3].deleted) == 0
    assert len(differentials[3].unchanged) == 1
    assert len(differentials[3].created) == 0
    assert differentials[3].unchanged[0].open().read() == b"On Both"


def test_likely_unchanged() -> None:
    # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
    mock_stat = stat_result([0o1777, 1, 2, 3, 1337, 7331, 999, 0, 0, 0])
    mock_stat_accessed = stat_result([0o1777, 1, 2, 3, 1337, 7331, 999, 999, 0, 0])
    mock_stat_changed = stat_result([0o1777, 1, 2, 3, 1337, 7331, 999, 999, 999, 0])

    assert likely_unchanged(mock_stat, mock_stat_accessed)
    assert not likely_unchanged(mock_stat, mock_stat_changed)


def test_differentiate_filesystems(src_target: Target, dst_target: Target) -> None:
    records = list(differentiate_target_filesystems(src_target, dst_target, deep=True, exclude="/etc/*"))

    created = [record for record in records if "created" in record._desc.name]
    modified = [record for record in records if "modified" in record._desc.name]
    deleted = [record for record in records if "deleted" in record._desc.name]

    assert len(created) == 6
    assert all(record._desc.name == "differential/file/created" for record in created)

    assert len(modified) == 1
    assert all(record._desc.name == "differential/file/modified" for record in modified)

    assert len(deleted) == 6
    assert all(record._desc.name == "differential/file/deleted" for record in deleted)


def test_differentiate_plugins(src_target: Target, dst_target: Target) -> None:
    records = list(differentiate_target_plugin_outputs(src_target, dst_target, plugin="users"))
    assert len(records) == 4

    created = [record for record in records if "created" in record._desc.name]
    unchanged = [record for record in records if "unchanged" in record._desc.name]
    deleted = [record for record in records if "deleted" in record._desc.name]

    assert len(unchanged) == 2
    assert len(created) == 1
    assert len(deleted) == 1

    assert created[0].record.name == "dst_user"
    assert created[0].record.hostname == "dst_target"
    assert deleted[0].record.name == "src_user"
    assert deleted[0].record.hostname == "src_target"


def test_shell_ls(
    src_target: Target, dst_target: Target, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fsutils, "LS_COLORS", {})

    cli = DifferentialCli(src_target, dst_target, deep=True)
    cli.onecmd("ls changes")

    captured = capsys.readouterr()

    expected = [
        "changed (modified)",
        "dir_on_src (created)",
        "dir_on_src (deleted)",
        "file_on_src (created)",
        "file_on_src (deleted)",
        "only_on_dst (created)",
        "only_on_src (deleted)",
        "subdirectory_both",
        "subdirectory_dst (created)",
        "subdirectory_src (deleted)",
        "unchanged",
    ]

    assert captured.out == "\n".join(expected) + "\n"


def test_shell_find(
    src_target: Target, dst_target: Target, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fsutils, "LS_COLORS", {})

    cli = DifferentialCli(src_target, dst_target, deep=True)
    cli.onecmd("find /changes -cmd")

    captured = capsys.readouterr()

    expected = [
        "/changes/changed (modified)",
        "/changes/dir_on_src (created)",
        "/changes/dir_on_src (deleted)",
        "/changes/file_on_src (created)",
        "/changes/file_on_src (deleted)",
        "/changes/only_on_dst (created)",
        "/changes/only_on_src (deleted)",
        "/changes/subdirectory_dst (created)",
        "/changes/subdirectory_src (deleted)",
        "/changes/subdirectory_dst/only_on_dst (created)",
        "/changes/file_on_src/file (created)",
        "/changes/subdirectory_src/only_on_src (deleted)",
        "/changes/dir_on_src/file (deleted)",
    ]

    assert captured.out == "\n".join(expected) + "\n"


def test_shell_cat(src_target: Target, dst_target: Target, capsys: pytest.CaptureFixture) -> None:
    cli = DifferentialCli(src_target, dst_target, deep=True)

    cli.onecmd("cat /changes/unchanged")
    captured = capsys.readouterr()
    assert captured.out == "Unchanged\n"

    cli.onecmd("cat /changes/subdirectory_dst/only_on_dst")
    captured = capsys.readouterr()
    assert captured.out == "Hello From Destination Target\n"

    cli.onecmd("cat /changes/subdirectory_src/only_on_src")
    captured = capsys.readouterr()
    assert captured.out == "Hello From Source Target\n"

    # When a file is present on both, we want the last version of the file to be outputted.
    cli.onecmd("cat /changes/changed")
    captured = capsys.readouterr()
    assert captured.out == "Hello From Destination Target\n"


def test_shell_plugin(src_target: Target, dst_target: Target, capsys: pytest.CaptureFixture) -> None:
    cli = DifferentialCli(src_target, dst_target, deep=True)

    cli.onecmd("plugin users")
    captured = capsys.readouterr()

    assert "differential/record/created" in captured.out
    assert "differential/record/unchanged" in captured.out
    assert "differential/record/deleted" in captured.out


def test_target_diff_shell(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        m.setattr(fsutils, "LS_COLORS", {})
        m.setenv("NO_COLOR", "1")
        src_target_path = str(absolute_path("_data/tools/diff/src.tar"))
        dst_target_path = str(absolute_path("_data/tools/diff/dst.tar"))
        m.setattr("sys.argv", ["target-diff", "--deep", "shell", src_target_path, dst_target_path])
        m.setattr("sys.stdin", StringIO("ls changes"))
        target_diff()
        out, err = capsys.readouterr()
        out = out.replace("(diff) src_target/dst_target:/$", "").strip()

        expected = [
            "changed (modified)",
            "only_on_dst (created)",
            "only_on_src (deleted)",
            "subdirectory_both",
            "subdirectory_dst (created)",
            "subdirectory_src (deleted)",
            "unchanged",
        ]

        assert out == "\n".join(expected)
        assert "unrecognized arguments" not in err


def test_target_diff_fs(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        src_target_path = str(absolute_path("_data/tools/diff/src.tar"))
        dst_target_path = str(absolute_path("_data/tools/diff/dst.tar"))
        m.setattr("sys.argv", ["target-diff", "--deep", "fs", "--strings", src_target_path, dst_target_path])
        target_diff()
        out, _ = capsys.readouterr()

        assert "differential/file/created" in out
        assert "differential/file/modified" in out
        assert "differential/file/deleted" in out


def test_target_diff_query(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        src_target_path = str(absolute_path("_data/tools/diff/src.tar"))
        dst_target_path = str(absolute_path("_data/tools/diff/dst.tar"))
        m.setattr("sys.argv", ["target-diff", "query", "--strings", "-f", "users", src_target_path, dst_target_path])
        target_diff()
        out, _ = capsys.readouterr()

        assert "differential/record/created" in out
        assert "differential/record/unchanged" in out
        assert "differential/record/deleted" in out


def test_target_diff_fs_reverse_read(target_unix_factory: TargetUnixFactory) -> None:
    """Test if we detect the difference in an appended file correctly."""

    src_target, fs_src = target_unix_factory.new("src_target")
    dst_target, fs_dst = target_unix_factory.new("dst_target")
    fs_src.map_file_fh("var/log/example.log", BytesIO(b"A" * 1024 * 20))
    fs_dst.map_file_fh("var/log/example.log", BytesIO(b"A" * 1024 * 20 + b"B" * 1024))

    comparison = TargetComparison(src_target, dst_target, deep=True)
    diff = comparison.scandir("/var/log")

    assert len(diff.modified) == 1
    assert diff.modified[0].path == "/var/log/example.log"
    assert diff.modified[0].diff == [
        b"--- \n",
        b"+++ \n",
        b"@@ -1 +1 @@\n",
        b"-" + b"A" * 10 * 1024,
        b"+" + (b"A" * 9216) + (b"B" * 1024),
    ]
