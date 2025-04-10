from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.shell.wget import WgetPlugin
from dissect.target.plugins.os.unix._os import UnixPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_wget_hsts(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if .wget-hsts files are parsed as expected."""
    fs_unix.map_file_fh("/etc/hostname", BytesIO(b"example.domain"))

    fs_unix.map_file_fh(
        "/home/user/.wget-hsts",
        BytesIO(
            textwrap.dedent(
                """
        # HSTS 1.0 Known Hosts database for GNU Wget.
        # Edit at your own risk.
        # <hostname>	<port>	<incl. subdomains>	<created>	<max-age>
        mozilla.org	0	0	1717171717	31536000
        google.com	0	1	1711711711	31536000
        www.python.org	0	1	1713143141	63072000
        github.com	0	1	1713371337	31536000
        """
            ).encode()
        ),
    )

    target_unix_users.add_plugin(UnixPlugin)
    target_unix_users.add_plugin(WgetPlugin)

    results = sorted(target_unix_users.wget.hsts(), key=lambda r: r.host)

    assert len(results) == 4
    assert [r.host for r in results] == [
        "github.com",
        "google.com",
        "mozilla.org",
        "www.python.org",
    ]

    assert results[0].hostname == "example"
    assert results[0].domain == "domain"
    assert results[0].username == "user"
    assert results[0].host == "github.com"
    assert not results[0].explicit_port
    assert results[0].include_subdomains
    assert results[0].ts_created == datetime(2024, 4, 17, 16, 28, 57, tzinfo=timezone.utc)
    assert results[0].max_age == datetime(2025, 4, 17, 16, 28, 57, tzinfo=timezone.utc)
    assert results[0].source == "/home/user/.wget-hsts"
