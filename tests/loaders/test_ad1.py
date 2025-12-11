from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import TargetError
from dissect.target.helpers import keychain
from dissect.target.loaders.ad1 import AD1Loader
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target]) -> None:
    """Test that we correctly use ``AD1Loader`` when opening a ``Target``."""

    path = absolute_path("_data/filesystems/ad1/encrypted-small.ad1")

    with pytest.raises(TargetError):
        opener(path)

    keychain.register_wildcard_value("password")
    target = opener(path)

    assert isinstance(target._loader, AD1Loader)
    assert target.path == path
    assert target.fs.path("C:/Users/user/Desktop/Data").is_dir()
