from __future__ import annotations

from typing import TYPE_CHECKING, Callable
from unittest.mock import patch

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.vmwarevm import VmwarevmLoader
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def mock_vmwarevm_dir(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "Test.vmwarevm"
    path.mkdir()
    (path / "Test.vmx").touch()
    (path / "mock.vmdk").touch()

    with patch("dissect.hypervisor.descriptor.vmx.VMX") as mock_vmx:
        mock_vmx.parse.return_value = mock_vmx
        mock_vmx.disks.return_value = ["mock.vmdk"]

        yield path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target], mock_vmwarevm_dir: Path) -> None:
    """Test that we correctly use ``VmwarevmLoader`` when opening a ``Target``."""
    with patch("dissect.target.container.open"), patch("dissect.target.target.Target.apply"):
        target = opener(mock_vmwarevm_dir)
        assert isinstance(target._loader, VmwarevmLoader)
        assert target.path == mock_vmwarevm_dir


def test_loader(mock_vmwarevm_dir: Path) -> None:
    """Test that ``VmwarevmLoader`` correctly loads a VMware VM directory."""
    loader = loader_open(mock_vmwarevm_dir)
    assert isinstance(loader, VmwarevmLoader)

    with patch("dissect.target.container.open") as mock_container_open:
        t = Target()
        loader.map(t)

        assert len(t.disks) == 1
        mock_container_open.assert_called_with(mock_vmwarevm_dir / "mock.vmdk")
