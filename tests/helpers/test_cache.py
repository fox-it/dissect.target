from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from dissect.target.helpers.cache import Cache
from dissect.target.plugins.os.windows.amcache import AmcachePlugin
from dissect.target.plugins.os.windows.ual import UalPlugin

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from dissect.target.target import Target


def test_cache_namespace(target_bare: Target) -> None:
    cache1 = Cache(AmcachePlugin.__call__, cls=AmcachePlugin)
    cache2 = Cache(UalPlugin.__call__, cls=UalPlugin)

    assert cache1.fname != cache2.fname
    assert cache1.fname == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.__call__"
    assert cache2.fname == "dissect.target.plugins.os.windows.ual.UalPlugin.__call__"

    target_bare._config.CACHE_DIR = "/tmp"
    assert (
        cache1.cache_path(target_bare, ("a", 1234)).stem
        == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.__call__.KCdhJywgMTIzNCk="
    )
    assert (
        cache2.cache_path(target_bare, ("b", 5678)).stem
        == "dissect.target.plugins.os.windows.ual.UalPlugin.__call__.KCdiJywgNTY3OCk="
    )


def test_cache_filename(target_win: Target) -> None:
    plugin1 = AmcachePlugin(target_win)
    plugin2 = UalPlugin(target_win)

    cache1 = Cache(AmcachePlugin.applications)
    cache2 = Cache(UalPlugin.client_access)
    cache3 = Cache(plugin1.applications)
    cache4 = Cache(plugin2.client_access)

    assert cache1.fname == cache3.fname == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications"
    assert cache2.fname == cache4.fname == "dissect.target.plugins.os.windows.ual.UalPlugin.client_access"

    target_win._config.CACHE_DIR = "/tmp"
    assert (
        cache1.cache_path(target_win, ()).stem
        == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications.KCk="
    )
    assert (
        cache2.cache_path(target_win, ()).stem == "dissect.target.plugins.os.windows.ual.UalPlugin.client_access.KCk="
    )
    assert (
        cache3.cache_path(target_win, ()).stem
        == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications.KCk="
    )
    assert (
        cache4.cache_path(target_win, ()).stem == "dissect.target.plugins.os.windows.ual.UalPlugin.client_access.KCk="
    )


def test_cache_write_failure_behavior(target_bare: Target, tmp_path: Path) -> None:
    """
    Specifically tests the 'Write Path' (Cache Miss) which returns a CacheWriter.
    We verify that CacheWriter acts as an Iterator even when the underlying
    plugin returns None (stops immediately).
    """
    target_bare._config.CACHE_DIR = str(tmp_path)

    # 1. Mock Plugin with two modes
    class MockPlugin:
        def __init__(self, target: Target):
            self.target = target

        def success(self) -> Iterator[str]:
            yield "success_data"

        def failure(self) -> Iterator[str]:
            if True:
                return None
            yield "unreachable"

    plugin = MockPlugin(target_bare)

    # 2. Setup Cache wrapper
    # We force output="yield" to use LineReader/CacheWriter
    # (mimicking the behavior of RecordWriter logic in a simpler test)
    def create_wrapper(func: Callable[..., Iterator[str]]) -> Callable[..., Iterator[str]]:
        cache = Cache(func)

        def wrapper(*args: Any, **kwargs: Any) -> Iterator[str]:
            return cache.call(*args, **kwargs)

        wrapper.__output__ = "yield"
        cache.wrapper = wrapper
        return wrapper

    wrap_success = create_wrapper(MockPlugin.success)
    wrap_failure = create_wrapper(MockPlugin.failure)

    # --- SCENARIO A: Success Case (Write Path) ---
    # This creates a CacheWriter.
    # IF CacheWriter is not wrapped in iter(), next() crashes here.
    gen_success = wrap_success(plugin)

    assert next(gen_success) == "success_data"
    # Exhaust it to ensure file write completes
    list(gen_success)

    # --- SCENARIO B: Failure Case (Write Path) ---
    # It creates a CacheWriter that wraps an empty generator.
    gen_failure = wrap_failure(plugin)

    # CRITICAL CHECK:
    # 1. It must be an iterator (iter(obj) is obj)
    # 2. calling next() should raise StopIteration, NOT TypeError
    assert iter(gen_failure) is gen_failure

    # CacheWriter should be an empty iterable
    with pytest.raises(StopIteration):
        next(gen_failure)
