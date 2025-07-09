from pathlib import Path

import pytest
from pytest_benchmark.fixture import BenchmarkFixture

from dissect.target import Target
from dissect.target.loader import Loader
from dissect.target.loaders.tar import TarLoader
from tests._utils import absolute_path


@pytest.mark.parametrize(
    "archive,loader",
    [
        ("_data/loaders/tar/test-windows-fs-c-relative.tar", TarLoader),
    ],
)
@pytest.mark.benchmark
def test_benchmark(benchmark: BenchmarkFixture, target_default: Target, archive: str, loader: Loader) -> None:
    file = Path(absolute_path(archive))

    benchmark(lambda: loader(file).map(target_default))
