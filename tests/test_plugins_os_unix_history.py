import textwrap
from io import BytesIO

from dissect.util.ts import from_unix
from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.os.unix.history import CommandHistoryPlugin


def test_commandhistory_with_timestamps(target_unix_users, fs_unix):
    commandhistory_data = """\
    #1648598339
    echo "this is a test"
    echo "O no. A line without timestamp"
    #1658578468
    exit
    """

    commandhistory2_data = """\
    echo "this for user 2"
    """

    fs_unix.map_file_fh(
        "/root/.bash_history",
        BytesIO(textwrap.dedent(commandhistory_data).encode()),
    )

    fs_unix.map_file_fh(
        "/home/user/.bash_history",
        BytesIO(textwrap.dedent(commandhistory2_data).encode()),
    )

    target_unix_users.add_plugin(CommandHistoryPlugin)

    results = list(target_unix_users.commandhistory())
    assert len(results) == 4

    assert results[0].ts == dt("2022-03-29T23:58:59Z")
    assert results[0].command == 'echo "this is a test"'
    assert results[0].source.as_posix() == "/root/.bash_history"

    assert results[1].ts is None
    assert results[1].command == 'echo "O no. A line without timestamp"'
    assert results[1].source.as_posix() == "/root/.bash_history"

    assert results[2].ts == dt("2022-07-23T12:14:28Z")
    assert results[2].command == "exit"
    assert results[2].source.as_posix() == "/root/.bash_history"

    assert results[3].source.as_posix() == "/home/user/.bash_history"


def test_commandhistory_without_timestamps(target_unix_users, fs_unix):
    commandhistory_data = """\
    echo "Test if basic commandhistory works" > /dev/null
    exit
    """

    fs_unix.map_file_fh(
        "/root/.zsh_history",
        BytesIO(textwrap.dedent(commandhistory_data).encode()),
    )

    target_unix_users.add_plugin(CommandHistoryPlugin)

    results = list(target_unix_users.commandhistory())
    assert len(results) == 2

    assert results[0].ts is None
    assert results[0].command == 'echo "Test if basic commandhistory works" > /dev/null'
    assert results[0].source.as_posix() == "/root/.zsh_history"

    assert results[1].ts is None
    assert results[1].command == "exit"
    assert results[1].source.as_posix() == "/root/.zsh_history"


def test_commandhistory_zsh_history(target_unix_users, fs_unix):
    commandhistory_data = """\
    : 1673860722:0;sudo apt install sl
    : :;
    echo "Whoops no timestamps"
    """

    fs_unix.map_file_fh(
        "/root/.zsh_history",
        BytesIO(textwrap.dedent(commandhistory_data).encode()),
    )

    target_unix_users.add_plugin(CommandHistoryPlugin)

    results = list(target_unix_users.commandhistory())
    assert len(results) == 2

    assert results[0].ts == from_unix(1673860722)
    assert results[0].command == "sudo apt install sl"
    assert results[0].source.as_posix() == "/root/.zsh_history"

    assert not results[1].ts
    assert results[1].command == 'echo "Whoops no timestamps"'
    assert results[1].source.as_posix() == "/root/.zsh_history"
