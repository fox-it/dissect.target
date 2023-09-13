import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.proc import ProcPlugin, ProcProcess
from dissect.target.target import Target


def test_process(target_linux_users: Target, fs_linux_proc: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)

    process = target_linux_users.proc.process(1)
    assert isinstance(process, ProcProcess)
    assert process.pid == 1
    assert process.name == "systemd"
    assert process.parent.name == "swapper"
    assert process.ppid == 0
    assert process.state == "Sleeping"
    assert str(process.runtime) == "1 day, 13:19:27.970000"
    assert process.starttime.isoformat() == "2023-04-03T22:10:54.300000+00:00"

    environ = list(process.environ())
    assert environ[0].variable == "VAR"
    assert environ[0].contents == "1"


def test_process_not_found(target_linux_users: Target, fs_linux_proc: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)
    with pytest.raises(ProcessLookupError) as exc:
        target_linux_users.proc.process(404)
    assert str(exc.value) == f"Process with PID 404 could not be found on target: {target_linux_users}"


def test_processes(target_linux_users: Target, fs_linux_proc: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)

    for process in target_linux_users.proc.processes():
        assert process.pid in (1, 2, 3, 1337)
        assert process.state in ("Sleeping", "Waking", "Running", "Wakekill")
        assert process.name in ("systemd", "kthread", "acquire", "sshd")
        assert process.starttime.isoformat() == "2023-04-03T22:10:54.300000+00:00"
        assert str(process.runtime) == "1 day, 13:19:27.970000"

        for env in process.environ():
            assert env.variable == "VAR"
            assert env.contents == "1"


def test_proc_plugin_incompatible(target_linux_users: Target, fs_linux: VirtualFilesystem):
    with pytest.raises(UnsupportedPluginError, match="No /proc directory found"):
        target_linux_users.add_plugin(ProcPlugin)
