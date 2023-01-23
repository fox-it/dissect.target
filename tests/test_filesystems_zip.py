import io
import zipfile
import pytest

from dissect.target import container
from dissect.target.filesystems.zip import ZipFilesystem


def _create_zip(prefix=""):
    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w")

    zf.writestr(zipfile.ZipInfo(f"{prefix}file_1"), "file 1 contents")
    zf.writestr(zipfile.ZipInfo(f"{prefix}file_2"), "file 2 contents")
    for i in range(100):
        zf.writestr(f"{prefix}dir/{i}", f"contents {i}")

    zf.close()
    buf.seek(0)
    return buf


@pytest.fixture
def zip_simple():
    yield _create_zip()


@pytest.fixture
def zip_base():
    yield _create_zip("base/")


@pytest.fixture
def zip_relative():
    yield _create_zip("./")


@pytest.mark.parametrize(
    "obj",
    [
        "zip_simple",
        "zip_base",
        "zip_relative",
    ],
)
def test_filesystems_zip(obj, request):
    fh = request.getfixturevalue(obj)

    assert ZipFilesystem.detect(fh)

    fs = ZipFilesystem(fh)
    assert isinstance(fs, ZipFilesystem)

    assert fs.get("./file_1").open().read() == b"file 1 contents"
    assert fs.get("./file_2").open().read() == b"file 2 contents"
    assert len(list(fs.glob("./dir/*"))) == 100
