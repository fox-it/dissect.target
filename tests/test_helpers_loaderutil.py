import pytest

from pathlib import Path

from dissect.target.helpers.loaderutil import parse_path_uri, URIPath
from dissect.target.loader import LOADERS_BY_SCHEME
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.filesystems.dir import DirectoryFilesystem


@pytest.mark.parametrize(
    "path, expected",
    [
        # None objects fall through (BC)
        (None, (None, None, {}, "")),
        # Path objects fall through (BC/DRY)
        (Path("path"), (Path("path"), None, {}, "")),
        # local strings fall through (BC)
        ("local", (Path("local"), None, {}, "")),
        # basic path just gets boxed
        ("/path/to/file", (Path("/path/to/file"), None, {}, "")),
        ("C:\\path\\to\\file", (Path("C:\\path\\to\\file"), None, {}, "")),
        # selects correct loader
        (
            "tar:///archive.tar.gz",
            (URIPath.path("tar", "", "", "/archive.tar.gz"), LOADERS_BY_SCHEME["tar"], {}, "tar"),
        ),
        # works with absolute path
        (
            "tar:///root/archive.tar.gz",
            (URIPath.path("tar", "", "", "/root/archive.tar.gz"), LOADERS_BY_SCHEME["tar"], {}, "tar"),
        ),
        # remote uri
        (
            "tar://127.0.0.1:1234?b=1",
            (URIPath.path("tar", "127.0.0.1", 1234, ""), LOADERS_BY_SCHEME["tar"], {"b": ["1"]}, "tar"),
        ),
        (
            "tar://127.0.0.1:1234/path/to/web?b=1",
            (URIPath.path("tar", "127.0.0.1", 1234, "/path/to/web"), LOADERS_BY_SCHEME["tar"], {"b": ["1"]}, "tar"),
        ),
        (
            "tar://127.0.0.1:1234//path/to/web?b=1",
            (URIPath.path("tar", "127.0.0.1", 1234, "//path/to/web"), LOADERS_BY_SCHEME["tar"], {"b": ["1"]}, "tar"),
        ),
        # normalized slashes
        (
            "tar://127.0.0.1:1234///path/to//////web2?b=1",
            (URIPath.path("tar", "127.0.0.1", 1234, "/path/to/web2"), LOADERS_BY_SCHEME["tar"], {"b": ["1"]}, "tar"),
        ),
        # file:// is same as nothing
        ("file:///root/archive.tar.gz", (URIPath.path("file", "", "", "/root/archive.tar.gz"), None, {}, "file")),
        # non-existant scheme yields None value, so equals file://
        ("fake:///root/archive", (URIPath.path("fake", "", "", "/root/archive"), None, {}, "fake")),
        # can we extract query parameters?
        ("fake:///root/archive?a=1", (URIPath.path("fake", "", "", "/root/archive"), None, {"a": ["1"]}, "fake")),
        # invalid url
        ("fake:///?a=1", (URIPath.path("fake", "", "", "/"), None, {"a": ["1"]}, "fake")),
        ("fake://?a=1", (URIPath.path("fake", "", "", ""), None, {"a": ["1"]}, "fake")),
        # unparseable url, gets treated as path
        ("://?a=1", (Path(":/?a=1"), None, {"a": ["1"]}, "")),
        ("aaa.bbb", (Path("aaa.bbb"), None, {}, "")),
        # relative paths
        (
            "vmx:///~/data/archive.zip?a=1",
            (URIPath.path("vmx", "", "", "/~/data/archive.zip"), LOADERS_BY_SCHEME["vmx"], {"a": ["1"]}, "vmx"),
        ),
        (
            "vmx:///../data/archive.zip?a=1",
            (URIPath.path("vmx", "", "", "/../data/archive.zip"), LOADERS_BY_SCHEME["vmx"], {"a": ["1"]}, "vmx"),
        ),
        # Targetpaths
        (TargetPath(DirectoryFilesystem("/")), (TargetPath(DirectoryFilesystem("/")), None, {}, "")),
    ],
)
def test_parse_path_uri(path, expected):
    assert parse_path_uri(path) == expected
