from io import BytesIO

from dissect.target.plugins.os.unix.locale import LocalePlugin as UnixLocalePlugin

from ._utils import absolute_path


def test_locale_plugin_unix(target_unix_users, fs_unix):
    # Locale locations originate from Ubuntu 20.
    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"Europe/Amsterdam"))
    fs_unix.map_file_fh("/etc/default/locale", BytesIO(b"LANG=en_US.UTF-8"))
    fs_unix.map_file("/etc/default/keyboard", absolute_path("data/unix/configs/keyboard"))
    target_unix_users.add_plugin(UnixLocalePlugin)

    assert target_unix_users.timezone == "Europe/Amsterdam"
    assert target_unix_users.language == ["en_US"]
    keyboard = list(target_unix_users.keyboard())
    assert len(keyboard) == 1
    assert keyboard[0].layout == "us"
    assert keyboard[0].model == "pc105"
    assert keyboard[0].variant == ""
    assert keyboard[0].options == ""
    assert keyboard[0].backspace == "guess"


def test_locale_plugin_unix_quotes(target_unix_users, fs_unix):
    # Older Fedora system
    fs_unix.map_file_fh("/etc/default/locale", BytesIO(b'LANG="en_US.UTF-8"'))
    target_unix_users.add_plugin(UnixLocalePlugin)

    assert target_unix_users.language == ["en_US"]
