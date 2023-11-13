from dissect.target.helpers.cache import Cache
from dissect.target.plugins.os.windows.amcache import AmcachePlugin
from dissect.target.plugins.os.windows.ual import UalPlugin


def test_cache_namespace(target_bare):
    cache1 = Cache(AmcachePlugin.__call__, cls=AmcachePlugin)
    cache2 = Cache(UalPlugin.__call__, cls=UalPlugin)

    assert cache1.fname != cache2.fname
    assert cache1.fname == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.__call__"
    assert cache2.fname == "dissect.target.plugins.os.windows.ual.UalPlugin.__call__"

    target_bare._config.CACHE_DIR = "/tmp"
    assert "dissect.target.plugins.os.windows.amcache.AmcachePlugin.__call__.KCdhJywgMTIzNCk=" in cache1.cache_path(
        target_bare, ("a", 1234)
    )
    assert "dissect.target.plugins.os.windows.ual.UalPlugin.__call__.KCdiJywgNTY3OCk=" in cache2.cache_path(
        target_bare, ("b", 5678)
    )


def test_cache_filename(target_bare):
    plugin1 = AmcachePlugin(target_bare)
    plugin2 = UalPlugin(target_bare)

    cache1 = Cache(AmcachePlugin.applications)
    cache2 = Cache(UalPlugin.client_access)
    cache3 = Cache(plugin1.applications)
    cache4 = Cache(plugin2.client_access)

    assert cache1.fname == cache3.fname == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications"
    assert cache2.fname == cache4.fname == "dissect.target.plugins.os.windows.ual.UalPlugin.client_access"

    target_bare._config.CACHE_DIR = "/tmp"
    assert "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications" in cache1.cache_path(target_bare, ())
    assert "dissect.target.plugins.os.windows.ual.UalPlugin.client_access" in cache2.cache_path(target_bare, ())
    assert "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications" in cache3.cache_path(target_bare, ())
    assert "dissect.target.plugins.os.windows.ual.UalPlugin.client_access" in cache4.cache_path(target_bare, ())
