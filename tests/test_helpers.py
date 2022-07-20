from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from dissect.target.helpers import config, keychain, docs
from dissect.target.plugins.os.windows.iis import IISLogsPlugin

from ._utils import absolute_path


def test_load_config():

    # FS layout:
    #
    # temp_dir1
    #   config_file
    #   symlink_dir2 -> ../temp_dir2
    # temp_dir2

    with TemporaryDirectory() as temp_dir1, TemporaryDirectory() as temp_dir2:

        # create symlink in temp_dir1 pointing to temp_dir2
        symlink = Path(temp_dir1).joinpath("symlink")
        symlink.symlink_to(temp_dir2)

        config_file = Path(temp_dir1).joinpath(config.CONFIG_NAME)
        config_file.write_text('raise Exception("config-file-found")')

        with pytest.raises(Exception, match="config-file-found"):
            config.load(str(symlink))


@pytest.fixture
def guarded_keychain():
    keychain.KEYCHAIN.clear()
    yield
    keychain.KEYCHAIN.clear()


def test_keychain_register_keychain_file(guarded_keychain):

    keychain_file = Path(absolute_path("data/keychain.csv"))

    keychain.register_keychain_file(keychain_file)

    assert len(keychain.get_keys_without_provider()) == 1
    assert len(keychain.get_keys_for_provider("some")) == 0
    assert len(keychain.get_keys_for_provider("bitlocker")) == 2


def test_keychain_register_wildcard_value(guarded_keychain):

    keychain.register_wildcard_value("test-value")

    # number of keys registered is equal number of supported key types
    assert len(keychain.get_keys_without_provider()) == len(keychain.KeyType)


def get_nonempty_lines_set(paragraph):
    return set(filter(None, (line.strip() for line in paragraph.splitlines())))


def test_docs_plugin_description():

    plugin_desc = docs.get_plugin_description(IISLogsPlugin)

    assert plugin_desc
    assert IISLogsPlugin.__name__ in plugin_desc

    assert get_nonempty_lines_set(IISLogsPlugin.__doc__).issubset(get_nonempty_lines_set(plugin_desc))


def test_docs_plugin_functions_desc():

    functions_short_desc = docs.get_plugin_functions_desc(IISLogsPlugin, with_docstrings=False)

    assert functions_short_desc
    desc_lines = functions_short_desc.splitlines()

    assert len(desc_lines) == 1
    assert "iis.logs" in functions_short_desc
    assert "Return contents of IIS (v7 and above) log files." in functions_short_desc
    assert "output: records" in functions_short_desc

    functions_long_desc = docs.get_plugin_functions_desc(IISLogsPlugin, with_docstrings=True)

    assert functions_long_desc

    lines_bag = get_nonempty_lines_set(functions_long_desc)

    assert "Return contents of IIS (v7 and above) log files." in lines_bag
    assert "Supported log formats: IIS, W3C." in lines_bag


def test_docs_get_func_description():
    func = IISLogsPlugin.logs
    func_desc = docs.get_func_description(func, with_docstrings=False)

    assert "iis.logs - Return contents of IIS (v7 and above) log files. (output: records)" == func_desc

    func_desc = docs.get_func_description(func, with_docstrings=True)
    lines_bag = get_nonempty_lines_set(func_desc)

    assert "Return contents of IIS (v7 and above) log files." in lines_bag
    assert "Supported log formats: IIS, W3C." in lines_bag
