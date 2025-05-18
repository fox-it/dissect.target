from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.cache import Cache
from dissect.target.plugins.os.windows.amcache import AmcachePlugin
from dissect.target.plugins.os.windows.ual import UalPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_cache_namespace(target_bare: Target) -> None:
    cache1 = Cache(AmcachePlugin.__call__, cls=AmcachePlugin)
    cache2 = Cache(UalPlugin.__call__, cls=UalPlugin)

    assert cache1.fname != cache2.fname
    assert cache1.fname == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.__call__"
    assert cache2.fname == "dissect.target.plugins.os.windows.ual.UalPlugin.__call__"

    target_bare._config.CACHE_DIR = "/tmp"
    assert (
        cache1.cache_path(target_bare, ("a", 1234)).name
        == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.__call__.KCdhJywgMTIzNCk=.zstd"
    )
    assert (
        cache2.cache_path(target_bare, ("b", 5678)).name
        == "dissect.target.plugins.os.windows.ual.UalPlugin.__call__.KCdiJywgNTY3OCk=.zstd"
    )


def test_cache_filename(target_bare: Target) -> None:
    plugin1 = AmcachePlugin(target_bare)
    plugin2 = UalPlugin(target_bare)

    cache1 = Cache(AmcachePlugin.applications)
    cache2 = Cache(UalPlugin.client_access)
    cache3 = Cache(plugin1.applications)
    cache4 = Cache(plugin2.client_access)

    assert cache1.fname == cache3.fname == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications"
    assert cache2.fname == cache4.fname == "dissect.target.plugins.os.windows.ual.UalPlugin.client_access"

    target_bare._config.CACHE_DIR = "/tmp"
    assert (
        cache1.cache_path(target_bare, ()).name
        == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications.KCk=.zstd"
    )
    assert (
        cache2.cache_path(target_bare, ()).name
        == "dissect.target.plugins.os.windows.ual.UalPlugin.client_access.KCk=.zstd"
    )
    assert (
        cache3.cache_path(target_bare, ()).name
        == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications.KCk=.zstd"
    )
    assert (
        cache4.cache_path(target_bare, ()).name
        == "dissect.target.plugins.os.windows.ual.UalPlugin.client_access.KCk=.zstd"
    )
