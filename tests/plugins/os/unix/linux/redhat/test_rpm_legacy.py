# Backported from dissect.database.bsd.tools.rpm
from __future__ import annotations

import gzip
import textwrap
from typing import TYPE_CHECKING, BinaryIO

import pytest
from dissect.database.bsd.db import DB

from dissect.target.plugins.os.unix.linux.redhat.rpm.rpm import Package
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator


def open_file_gz(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), mode) as fh:
        yield fh


@pytest.fixture
def rpm_package() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/plugins/os/unix/linux/redhat/rpm/legacy/Packages.gz")


def test_rpm_legacy(rpm_package: BinaryIO) -> None:
    """Test parsing RPM Packages file."""
    # Manually unpacks Berkley DB records instead of using ``parse_package``.
    db = DB(rpm_package)
    packages = [Package(blob) for i, (_, blob) in enumerate(db.records()) if i > 0]

    assert len(packages) == 239

    entry = packages[27]
    assert entry.name == "python"
    assert entry.version == "2.6.6"
    assert entry.release == "68.el6_10"
    assert entry.summary == "An interpreted, interactive, object-oriented programming language"

    desc = """
    Python is an interpreted, interactive, object-oriented programming
    language often compared to Tcl, Perl, Scheme or Java. Python includes
    modules, classes, exceptions, very high level dynamic data types and
    dynamic typing. Python supports interfaces to many system calls and
    libraries, as well as to various windowing systems (X11, Motif, Tk,
    Mac and MFC).

    Programmers can write new built-in modules for Python in C or C++.
    Python can be used as an extension language for applications that need
    a programmable interface.

    Note that documentation for Python is provided in the python-docs
    package.

    This package provides the "python" executable; most of the actual
    implementation is within the "python-libs" package."""
    assert entry.description == textwrap.dedent(desc).strip()

    files = list(entry)
    assert len(files) == 8
    assert [f.path for f in files] == [
        "/usr/bin/pydoc",
        "/usr/bin/python",
        "/usr/bin/python2",
        "/usr/bin/python2.6",
        "/usr/share/doc/python-2.6.6",
        "/usr/share/doc/python-2.6.6/LICENSE",
        "/usr/share/doc/python-2.6.6/README",
        "/usr/share/man/man1/python.1.gz",
    ]
