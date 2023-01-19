from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

UnixKeyboardRecord = TargetRecordDescriptor(
    "linux/keyboard",
    [
        ("string", "layout"),
        ("string", "model"),
        ("string", "variant"),
        ("string", "options"),
        ("string", "backspace"),
    ],
)


class LocalePlugin(Plugin):
    def check_compatible(self):
        pass

    @export(property=True)
    def timezone(self):
        """Get the timezone of the system."""

        # /etc/timezone should contain a simple timezone string
        # on most unix systems
        if (path := self.target.fs.path("/etc/timezone")).exists():
            for line in path.open("rt"):
                return line.strip()

        # /etc/localtime should be a symlink to
        # eg. /usr/share/zoneinfo/America/New_York
        # on centos and some other distros
        if (zoneinfo := self.target.fs.path("/etc/localtime")).exists():
            zoneinfo_path = str(zoneinfo.readlink()).split("/")
            timezone = "/".join(zoneinfo_path[-2:])
            return timezone

    @export(property=True)
    def language(self):
        """Get the configured locale(s) of the system."""
        locale_paths = ["/etc/default/locale", "/etc/locale.conf"]

        found_languages = []

        for locale_path in locale_paths:
            if (path := self.target.fs.path(locale_path)).exists():
                for line in path.open("rt"):
                    if "LANG=" in line:
                        found_languages.append(
                            line.replace("LANG=", "").replace('"', "").replace(".UTF-8", "").replace("_", "-").strip()
                        )

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
                        k[key_value[0].replace("XKB", "").replace("KEYMAP", "LAYOUT")] = (
                            key_value[1].replace('"', "").strip()
                        )

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
