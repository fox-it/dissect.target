from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.helpers.localeutil import normalize_language
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.os.default.locale import LocalePlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

UnixKeyboardRecord = TargetRecordDescriptor(
    "unix/keyboard",
    [
        ("string", "layout"),
        ("string", "model"),
        ("string", "variant"),
        ("string", "options"),
        ("string", "backspace"),
    ],
)


def timezone_from_path(path: Path | str) -> str:
    """Return timezone name for the given zoneinfo path.

    .. code-block::

        /usr/share/zoneinfo/Europe/Amsterdam -> Europe/Amsterdam
        /usr/share/zoneinfo/UTC              -> UTC
        Etc/UTC                              -> UTC
    """
    if not isinstance(path, Path):
        path = Path(path)

    return "/".join([p for p in path.parts[-2:] if p.lower() not in ["zoneinfo", "etc"]])


class UnixLocalePlugin(LocalePlugin):
    """Unix locale plugin."""

    def check_compatible(self) -> None:
        pass

    @export(property=True)
    def timezone(self) -> str | None:
        """Get the timezone of the system."""

        # /etc/timezone should contain a simple timezone string
        # on most unix systems
        if (path := self.target.fs.path("/etc/timezone")).exists():
            for line in path.open("rt"):
                return timezone_from_path(Path(line.strip()))

        # /etc/localtime can be a symlink, hardlink or a copy of:
        # eg. /usr/share/zoneinfo/America/New_York
        p_localtime = self.target.fs.path("/etc/localtime")

        # If it's a symlink, read the path of the symlink
        if p_localtime.is_symlink():
            return timezone_from_path(p_localtime.readlink())

        # If it's a hardlink, try finding the hardlinked zoneinfo file
        if p_localtime.exists() and p_localtime.stat().st_nlink > 1:
            for path in self.target.fs.path("/usr/share/zoneinfo").rglob("*"):
                if p_localtime.samefile(path):
                    return timezone_from_path(path)

        # If it's a regular file (probably copied), we try finding it by matching size and sha1 hash.
        if p_localtime.is_file():
            size = p_localtime.stat().st_size
            sha1 = p_localtime.get().sha1()
            for path in self.target.fs.path("/usr/share/zoneinfo").rglob("*"):
                # Ignore posix files in zoneinfo directory (RHEL).
                if path.name.startswith("posix"):
                    continue

                if path.is_file() and path.stat().st_size == size and path.get().sha1() == sha1:
                    return timezone_from_path(path)
            return None
        return None

    @export(property=True)
    def language(self) -> list[str]:
        """Get the configured locale(s) of the system."""

        # Although this purports to be a generic function for Unix targets, these paths are Linux specific.
        locale_paths = [
            "/etc/default/locale",
            "/etc/locale.conf",
            "/etc/sysconfig/i18n",
        ]

        found_languages = set()

        for locale_path in locale_paths:
            if (path := self.target.fs.path(locale_path)).exists():
                for line in path.open("rt"):
                    if "LANG=" in line:
                        lang_str = line.partition("=")[-1].strip().strip('"')
                        if lang_str == "C.UTF-8":  # Skip if no locales are installed.
                            continue
                        found_languages.add(normalize_language(lang_str))

        return list(found_languages)

    @export(record=UnixKeyboardRecord)
    def keyboard(self) -> Iterator[UnixKeyboardRecord]:
        """Get the keyboard layout(s) of the system."""

        paths = [
            "/etc/default/keyboard",
            "/etc/vconsole.conf",
            *list(self.target.fs.glob("/etc/X11/xorg.conf.d/*-keyboard.conf")),
        ]

        for path_ in paths:
            if (path := self.target.fs.path(path_)).exists():
                k = {}
                for line in path.open("rt"):
                    if len(key_value := line.split("=")) == 2:
                        k[key_value[0].replace("XKB", "").replace("KEYMAP", "LAYOUT")] = key_value[1].strip().strip('"')

                yield UnixKeyboardRecord(
                    layout=k.get("LAYOUT"),
                    model=k.get("MODEL"),
                    variant=k.get("VARIANT"),
                    options=k.get("OPTIONS"),
                    backspace=k.get("BACKSPACE"),
                    _target=self.target,
                )

        # TODO
        # /etc/sysconfig/keyboard
        # /usr/share/kbd/keymaps/*
        # /usr/local/share/kbd/keymaps/*
