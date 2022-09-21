from dissect.target.helpers.cache import Cache
from dissect.target.plugins.os.windows.amcache import AmcachePlugin
from dissect.target.plugins.os.windows.ual import UalPlugin


def test_cache_namespace(mock_target):
    cache1 = Cache(AmcachePlugin.__call__, cls=AmcachePlugin)
    cache2 = Cache(UalPlugin.__call__, cls=UalPlugin)

    assert cache1.fname != cache2.fname
    assert cache1.fname == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.__call__"
    assert cache2.fname == "dissect.target.plugins.os.windows.ual.UalPlugin.__call__"

    mock_target._config.CACHE_DIR = "/tmp"
    assert "dissect.target.plugins.os.windows.amcache.AmcachePlugin.__call__.KCdhJywgMTIzNCk=" in cache1.cache_path(
        mock_target, ("a", 1234)
    )
    assert "dissect.target.plugins.os.windows.ual.UalPlugin.__call__.KCdiJywgNTY3OCk=" in cache2.cache_path(
        mock_target, ("b", 5678)
    )


def test_cache_filename(mock_target):
    plugin1 = AmcachePlugin(mock_target)
    plugin2 = UalPlugin(mock_target)

    cache1 = Cache(AmcachePlugin.applications)
    cache2 = Cache(UalPlugin.client_access)
    cache3 = Cache(plugin1.applications)
    cache4 = Cache(plugin2.client_access)

    assert cache1.fname == cache3.fname == "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications"
    assert cache2.fname == cache4.fname == "dissect.target.plugins.os.windows.ual.UalPlugin.client_access"

    mock_target._config.CACHE_DIR = "/tmp"
    assert "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications" in cache1.cache_path(mock_target, ())
    assert "dissect.target.plugins.os.windows.ual.UalPlugin.client_access" in cache2.cache_path(mock_target, ())
    assert "dissect.target.plugins.os.windows.amcache.AmcachePlugin.applications" in cache3.cache_path(mock_target, ())
    assert "dissect.target.plugins.os.windows.ual.UalPlugin.client_access" in cache4.cache_path(mock_target, ())
