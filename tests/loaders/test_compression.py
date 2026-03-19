from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.loaders.compression import CompressionLoader
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


@pytest.mark.parametrize(
    "archive",
    [
        "_data/loaders/tar/test-archive.tar.gz",
    ],
)
@pytest.mark.benchmark
def test_benchmark(benchmark: BenchmarkFixture, archive: str) -> None:
    """Benchmark the loading of archives."""
    file = absolute_path(archive)

    benchmark(lambda: CompressionLoader(file).map(Target()))
