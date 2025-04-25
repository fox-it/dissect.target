from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING
from unittest.mock import patch

from dissect.target.plugin import load_modules_from_paths

if TYPE_CHECKING:
    from pathlib import Path


def test_registration(tmp_path: Path) -> None:
    code = """
        from pathlib import Path

        from dissect.target import container
        from dissect.target.loader import Loader, register
        from dissect.target.target import Target


        class TestLoader(Loader):
            @staticmethod
            def detect(path: Path) -> bool:
                return False

            def map(self, target: Target) -> None:
                target.disks.add(container.open(self.path))


        register(__name__, TestLoader.__name__, internal=False)
    """
    (tmp_path / "loader.py").write_text(textwrap.dedent(code))

    with (
        patch("dissect.target.loader.LOADERS", []) as mocked_loaders,
        patch("dissect.target.loader.LOADERS_BY_SCHEME", {}),
    ):
        load_modules_from_paths([tmp_path])

        assert len(mocked_loaders) == 1
        assert mocked_loaders[0].__name__ == "TestLoader"
