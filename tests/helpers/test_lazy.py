from __future__ import annotations

from types import ModuleType
from unittest.mock import patch

import pytest

from dissect.target.helpers.lazy import import_lazy


def test_working() -> None:
    mock_module = ModuleType("mock")
    mock_module.function = lambda: "foo"

    with patch("importlib.import_module") as mock_import_module:
        mock_import_module.return_value = mock_module

        lazy_mod = import_lazy("mock")
        lazy_attr = lazy_mod.function

        assert repr(lazy_mod) == "<lazy mock loaded=False failed=False>"
        assert repr(lazy_attr) == "<lazyattr mock.function loaded=False failed=False>"

        assert lazy_attr() == "foo"

        assert repr(lazy_mod) == "<lazy mock loaded=True failed=False>"
        assert repr(lazy_attr) == "<lazyattr mock.function loaded=True failed=False>"


def test_failing_import() -> None:
    with patch("importlib.import_module") as mock_import_module:
        mock_import_module.side_effect = ImportError("Module not found")

        lazy_mod = import_lazy("nonexistent")
        lazy_attr = lazy_mod.function

        with pytest.raises(ImportError, match="Failed to lazily import nonexistent: Module not found"):
            lazy_attr()

        assert repr(lazy_mod) == "<lazy nonexistent loaded=True failed=True>"
        assert repr(lazy_attr) == "<lazyattr nonexistent.function loaded=True failed=True>"


def test_missing_attr() -> None:
    mock_module = ModuleType("mock")

    with patch("importlib.import_module") as mock_import_module:
        mock_import_module.return_value = mock_module

        lazy_mod = import_lazy("mock")
        lazy_attr = lazy_mod.function

        with pytest.raises(AttributeError, match="module 'mock' has no attribute 'function'"):
            lazy_attr()

        assert repr(lazy_mod) == "<lazy mock loaded=True failed=False>"
        assert repr(lazy_attr) == "<lazyattr mock.function loaded=True failed=True>"
