from __future__ import annotations

import pytest

from dissect.target import exceptions


@pytest.mark.parametrize(
    ("exc", "std"),
    [
        (exceptions.FileNotFoundError, FileNotFoundError),
        (exceptions.IsADirectoryError, IsADirectoryError),
        (exceptions.NotADirectoryError, NotADirectoryError),
    ],
)
def test_filesystem_error_subclass(exc: exceptions.Error, std: Exception) -> None:
    assert issubclass(exc, (std, exceptions.FilesystemError))
    assert isinstance(exc(), (std, exceptions.FilesystemError))

    with pytest.raises(std):
        raise exc()
