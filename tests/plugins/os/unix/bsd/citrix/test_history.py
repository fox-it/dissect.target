from __future__ import annotations

import datetime
import gzip
import textwrap
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.bsd.citrix.history import CitrixCommandHistoryPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_netscaler_bash_history_absolute_path_glob(target_citrix: Target, fs_bsd: VirtualFilesystem) -> None:
    commandhistory_data = """\
    Aug  9 12:56:00 <local7.notice> ns bash[23841]: root on /dev/pts/0 shell_command="find . -name '*ci.php*'"
    Aug 10 11:57:39 <local7.notice> ns bash[56440]: (null) on /dev/pts/1 shell_command="debug "hello world""
    """

    fs_bsd.map_file_fh(
        "/var/log/bash.log",
        BytesIO(textwrap.dedent(commandhistory_data).encode()),
    )

    target_citrix.add_plugin(CitrixCommandHistoryPlugin)

    results = list(target_citrix.commandhistory())
    assert len(results) == 2
    # Due to the usage of year_rollover_helper, the results are returned back-to-front. Moreover, it takes the
    # year from the file's mtime, which in this mocked version is epoch 0 (thus the year 1970)
    assert results[1].ts == datetime.datetime(1970, 8, 9, 12, 56, 0, tzinfo=datetime.timezone.utc)
    assert results[1].command == "find . -name '*ci.php*'"
    assert results[1].order == -1
    assert results[1].shell == "citrix-netscaler-bash"
    assert results[1].source.as_posix() == "/var/log/bash.log"

    assert results[0].ts == datetime.datetime(1970, 8, 10, 11, 57, 39, tzinfo=datetime.timezone.utc)
    assert results[0].command == 'debug "hello world"'
    assert results[0].order == 0
    assert results[0].shell == "citrix-netscaler-bash"
    assert results[0].source.as_posix() == "/var/log/bash.log"


def test_netscaler_commandhistory_decompress(target_citrix: Target, fs_bsd: VirtualFilesystem) -> None:
    commandhistory_data = """\
    Aug  9 12:56:00 <local7.notice> ns bash[23841]: root on /dev/pts/0 shell_command="find . -name '*ci.php*'"
    Aug 10 11:57:39 <local7.notice> ns bash[56440]: (null) on /dev/pts/1 shell_command="debug "hello world""
    """

    fs_bsd.map_file_fh(
        "/var/log/bash.log.0.gz",
        BytesIO(gzip.compress(textwrap.dedent(commandhistory_data).encode())),
    )

    target_citrix.add_plugin(CitrixCommandHistoryPlugin)

    results = list(target_citrix.commandhistory())
    assert len(results) == 2
    # Due to the usage of year_rollover_history, the results are returned back-to-front
    assert results[1].ts == datetime.datetime(1970, 8, 9, 12, 56, 0, tzinfo=datetime.timezone.utc)
    assert results[1].command == "find . -name '*ci.php*'"
    assert results[1].order == -1
    assert results[1].shell == "citrix-netscaler-bash"
    assert results[1].source.as_posix() == "/var/log/bash.log.0.gz"

    assert results[0].ts == datetime.datetime(1970, 8, 10, 11, 57, 39, tzinfo=datetime.timezone.utc)
    assert results[0].command == 'debug "hello world"'
    assert results[0].order == 0
    assert results[0].shell == "citrix-netscaler-bash"
    assert results[0].source.as_posix() == "/var/log/bash.log.0.gz"


def test_netscaler_cli_history(target_citrix: Target, fs_bsd: VirtualFilesystem) -> None:
    commandhistory_data = """\
    _HiStOrY_V2_
    help
    shell
    """

    fs_bsd.map_file_fh("/var/nstmp/user/.nscli_history", BytesIO(textwrap.dedent(commandhistory_data).encode()))

    target_citrix.add_plugin(CitrixCommandHistoryPlugin)

    results = list(target_citrix.commandhistory())
    assert len(results) == 2

    assert not results[0].ts
    assert results[0].command == "help"
    assert results[0].order == 0
    assert results[0].shell == "citrix-netscaler-cli"
    assert results[0].source.as_posix() == "/var/nstmp/user/.nscli_history"

    assert not results[1].ts
    assert results[1].command == "shell"
    assert results[1].order == 1
    assert results[1].shell == "citrix-netscaler-cli"
    assert results[1].source.as_posix() == "/var/nstmp/user/.nscli_history"
