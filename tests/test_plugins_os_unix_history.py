import textwrap
from io import BytesIO

import pytest
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
    assert results[0].shell == "bash"
    assert results[0].source.as_posix() == "/root/.bash_history"

    assert results[1].ts is None
    assert results[1].command == 'echo "O no. A line without timestamp"'
    assert results[1].shell == "bash"
    assert results[1].source.as_posix() == "/root/.bash_history"

    assert results[2].ts == dt("2022-07-23T12:14:28Z")
    assert results[2].command == "exit"
    assert results[2].shell == "bash"
    assert results[2].source.as_posix() == "/root/.bash_history"

    assert results[3].ts is None
    assert results[3].command == 'echo "this for user 2"'
    assert results[3].shell == "bash"
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
    assert results[0].shell == "zsh"
    assert results[0].source.as_posix() == "/root/.zsh_history"

    assert results[1].ts is None
    assert results[1].command == "exit"
    assert results[1].shell == "zsh"
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
    assert results[0].shell == "zsh"
    assert results[0].source.as_posix() == "/root/.zsh_history"

    assert not results[1].ts
    assert results[1].command == 'echo "Whoops no timestamps"'
    assert results[1].shell == "zsh"
    assert results[1].source.as_posix() == "/root/.zsh_history"


def test_commandhistory_fish_history(target_unix_users, fs_unix):
    commandhistory_data = """
    - cmd: ls
      when: 1688642435
    - cmd: cd home/
      when: 1688642441
      paths:
        - home/
    - cmd: echo "test: test"
      when: 1688986629
    """

    fs_unix.map_file_fh(
        "/root/.local/share/fish/fish_history",
        BytesIO(textwrap.dedent(commandhistory_data).encode()),
    )

    target_unix_users.add_plugin(CommandHistoryPlugin)

    results = list(target_unix_users.commandhistory())
    assert len(results) == 3

    assert results[0].ts == from_unix(1688642435)
    assert results[0].command == "ls"
    assert results[0].shell == "fish"
    assert results[0].source.as_posix() == "/root/.local/share/fish/fish_history"

    assert results[1].ts == from_unix(1688642441)
    assert results[1].command == "cd home/"
    assert results[1].shell == "fish"
    assert results[1].source.as_posix() == "/root/.local/share/fish/fish_history"

    assert results[2].ts == from_unix(1688986629)
    assert results[2].command == 'echo "test: test"'
    assert results[2].shell == "fish"
    assert results[2].source.as_posix() == "/root/.local/share/fish/fish_history"


@pytest.mark.parametrize(
    "db_type, db_file, db_history",
    [
        (
            "mongodb",
            ".dbshell",
            """
            db
            print("Hello World")
            db.users.find({ name: /foo/i }, { _id: 0, name: 1})
            """,
        ),
        (
            "postgresql",
            ".psql_history",
            """
            \\l
            \\c example
            \\dt
            select * from users;
            """,
        ),
        (
            "mysql",
            ".mysql_history",
            """
            show databases;
            use example;
            show tables;
            select * from users;
            """,
        ),
        (
            "sqlite",
            ".sqlite_history",
            """
            .help
            create table tbl1(one text, two int);
            insert into tbl1 values('hello!', 10);
            insert into tbl1 values('goodbye', 20);
            select * from tbl1;
            """,
        ),
    ],
)
def test_commandhistory_database_history(target_unix_users, fs_unix, db_type, db_file, db_history):
    history_content = textwrap.dedent(db_history)
    history_lines = history_content.strip().split("\n")
    fs_unix.map_file_fh(
        f"/root/{db_file}",
        BytesIO(history_content.encode()),
    )

    target_unix_users.add_plugin(CommandHistoryPlugin)

    results = list(target_unix_users.commandhistory())

    assert len(results) == len(history_lines)

    for i, line in enumerate(history_lines):
        assert results[i].ts is None
        assert results[i].command == line
        assert results[i].shell == db_type
        assert results[i].source.as_posix() == f"/root/{db_file}"
