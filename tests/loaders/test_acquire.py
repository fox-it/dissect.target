from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.loaders.tar import TarLoader
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

    from dissect.target.loader import Loader


@pytest.mark.parametrize(
    ("archive", "loader"),
    [
        ("_data/loaders/tar/test-windows-fs-c-relative.tar", TarLoader),
    ],
)
@pytest.mark.benchmark
def test_benchmark(benchmark: BenchmarkFixture, archive: str, loader: type[Loader]) -> None:
    file = absolute_path(archive)

    benchmark(lambda: loader(file).map(Target()))
