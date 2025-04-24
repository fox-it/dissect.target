import pytest

from dissect.target import loader


@pytest.fixture(scope="module", autouse=True)
def reset_loaders() -> None:
    for ldr in loader.LOADERS:
        ldr.module._module = None
