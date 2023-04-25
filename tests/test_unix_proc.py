from io import BytesIO

import pytest

from dissect.target.filesystem import VirtualSymlink
from dissect.target.plugins.os.unix.proc import ProcPlugin, ProcProcess


def setup_procfs(fs_unix):
    procs = (
        ("proc/1", VirtualSymlink(fs_unix, "/proc/1/fd/4", "socket:[1337]"), "test\x00cmdline\x00", "VAR=1"),
        ("proc/2", VirtualSymlink(fs_unix, "/proc/2/fd/4", "socket:[1338]"), "\x00", "VAR=1\x00"),
        ("proc/3", VirtualSymlink(fs_unix, "/proc/3/fd/4", "socket:[1339]"), "sshd", "VAR=1"),
        (
            "proc/1337",
            VirtualSymlink(fs_unix, "/proc/1337/fd/4", "socket:[1337]"),
            "acquire\x00-p\x00full\x00--proc\x00",
            "VAR=1",
        ),
    )
    stat_files_data = (
        "1 (systemd) S 0 1 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
        "2 (kthread) K 1 1 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
        "3 (sshd) W 1 2 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
        "1337 (acquire) R 3 1 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
    )

    for idx, proc in enumerate(procs):
        dir, fd, cmdline, environ = proc
        fs_unix.makedirs(dir)
        fs_unix.map_file_entry(fd.path, fd)

        fs_unix.map_file_fh(dir + "/stat", BytesIO(stat_files_data[idx].encode()))
        fs_unix.map_file_fh(dir + "/cmdline", BytesIO(cmdline.encode()))
        fs_unix.map_file_fh(dir + "/environ", BytesIO(environ.encode()))

    # symlink acquire process to self
    fs_unix.link("/proc/1337", "/proc/self")

    # boottime and uptime are needed for for time tests
    fs_unix.map_file_fh("/proc/uptime", BytesIO(b"134368.27 132695.52\n"))
    fs_unix.map_file_fh("/proc/stat", BytesIO(b"btime 1680559854"))


def test_process(target_unix_users, fs_unix):
    setup_procfs(fs_unix)
    target_unix_users.add_plugin(ProcPlugin)

    process = target_unix_users.proc.process(1)
    assert type(process) == ProcProcess
    assert process.pid == 1
    assert process.name == "systemd"
    assert process.parent.name == "swapper"
    assert process.ppid == 0
    assert process.state == "Sleeping"
    assert str(process.runtime) == "1 day, 13:19:27.970000"
    assert process.starttime.isoformat() == "2023-04-03T22:10:54.300000+00:00"

    environ = list(process.environ())
    assert environ[0].variable == b"VAR"
    assert environ[0].contents == b"1"


def test_process_not_found(target_unix_users, fs_unix):
    setup_procfs(fs_unix)
    target_unix_users.add_plugin(ProcPlugin)
    with pytest.raises(ProcessLookupError) as exc:
        target_unix_users.proc.process(404)
    assert str(exc.value) == f"Process with PID 404 could not be found on target: {target_unix_users}"


def test_processes(target_unix_users, fs_unix):
    setup_procfs(fs_unix)
    target_unix_users.add_plugin(ProcPlugin)

    for process in target_unix_users.proc.processes():
        assert process.pid in (1, 2, 3, 1337)
        assert process.state in ("Sleeping", "Paging", "Running", "Wakekill")
        assert process.name in ("systemd", "kthread", "acquire", "sshd")
        assert process.starttime.isoformat() == "2023-04-03T22:10:54.300000+00:00"
        assert str(process.runtime) == "1 day, 13:19:27.970000"

        for env in process.environ():
            assert env.variable == b"VAR"
            assert env.contents == b"1"
