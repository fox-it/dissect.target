from pathlib import Path

from dissect.target.helpers.localeutil import normalize_language
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

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


def timezone_from_path(path: Path) -> str:
    """Return timezone name for given zoneinfo path.

    /usr/share/zoneinfo/Europe/Amsterdam -> Europe/Amsterdam
    """
    zoneinfo_path = str(path).split("/")
    return "/".join(zoneinfo_path[-2:])


class LocalePlugin(Plugin):
    def check_compatible(self) -> None:
        pass

    @export(property=True)
    def timezone(self):
        """Get the timezone of the system."""

        # /etc/timezone should contain a simple timezone string
        # on most unix systems
        if (path := self.target.fs.path("/etc/timezone")).exists():
            for line in path.open("rt"):
                return line.strip()

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
                if path.is_file() and path.stat().st_size == size and path.get().sha1() == sha1:
                    return timezone_from_path(path)

    @export(property=True)
    def language(self):
        """Get the configured locale(s) of the system."""
        # Although this purports to be a generic function for Unix targets,
        # these paths are Linux specific.
        locale_paths = ["/etc/default/locale", "/etc/locale.conf"]

        found_languages = []

        for locale_path in locale_paths:
            if (path := self.target.fs.path(locale_path)).exists():
                for line in path.open("rt"):
                    if "LANG=" in line:
                        found_languages.append(normalize_language(line.replace("LANG=", "").strip().strip('"')))

        return found_languages

    @export(record=UnixKeyboardRecord)
    def keyboard(self):
        """Get the keyboard layout(s) of the system."""

        paths = ["/etc/default/keyboard", "/etc/vconsole.conf"] + list(
            self.target.fs.glob("/etc/X11/xorg.conf.d/*-keyboard.conf")
        )

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
