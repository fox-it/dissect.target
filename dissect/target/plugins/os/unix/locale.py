from dissect.target.exceptions import FileNotFoundError
from dissect.target.helpers.record import UnixKeyboardRecord
from dissect.target.plugin import Plugin, export


class LocalePlugin(Plugin):
    def __init__(self, target):
        super().__init__(target)

    def check_compatible(self):
        pass

    @export(property=True)
    def timezone(self):
        """
        Get the timezone of the system.
        """

        # /etc/timezone should contain a simple timezone string
        # on most unix systems
        try:
            for line in self.target.fs.path("/etc/timezone").open("rt"):
                return line.strip()
        except FileNotFoundError:
            pass

        # /etc/localtime should be a symlink to
        # eg. /usr/share/zoneinfo/America/New_York
        # on centos and some other distros
        zoneinfo = self.target.fs.path("/etc/localtime")

        if zoneinfo.exists():
            zoneinfo_path = str(zoneinfo.readlink()).split("/")
            timezone = "/".join(zoneinfo_path[-2:])
            return timezone

        return

    @export(property=True)
    def language(self):
        """
        Get the configured locale(s) of the system.
        """
        locale_paths = ["/etc/default/locale", "/etc/locale.conf"]

        for locale_path in locale_paths:
            try:
                for line in self.target.fs.path(locale_path).open("rt"):
                    if "LANG=" in line:
                        return line.replace("LANG=", "").replace('"', "").strip()
                return
            except FileNotFoundError:
                pass

    @export(record=UnixKeyboardRecord)
    def keyboard(self):
        """
        Get the keyboard layout(s) of the system.
        """

        # FIXME: Shorten this dirty unix keyboard spaghetti code

        k = {"LAYOUT": None, "MODEL": None, "VARIANT": None, "OPTIONS": None, "BACKSPACE": None}

        # /etc/default/keyboard
        XKB = ["XKBMODEL", "XKBLAYOUT", "XKBVARIANT", "XKBOPTIONS", "BACKSPACE"]
        try:
            for line in self.target.fs.path("/etc/default/keyboard").open("rt"):
                for x in XKB:
                    if x in line:
                        k[x.replace("XKB", "")] = line.replace(x + "=", "").replace('"', "").strip()

            yield UnixKeyboardRecord(
                layout=k["LAYOUT"],
                model=k["MODEL"],
                variant=k["VARIANT"],
                options=k["OPTIONS"],
                backspace=k["BACKSPACE"],
                _target=self.target,
            )

        except FileNotFoundError:
            pass

        if k["LAYOUT"] is not None:
            return

        # /etc/vconsole.conf
        try:
            for line in self.target.fs.path("/etc/vconsole.conf").open("rt"):
                if "KEYMAP" in line:
                    k["LAYOUT"] = line.replace("KEYMAP=", "").replace('"', "").strip()
                    yield UnixKeyboardRecord(
                        layout=k["LAYOUT"],
                        _target=self.target,
                    )
        except FileNotFoundError:
            pass

        if k["LAYOUT"] is not None:
            return

        # /etc/X11/xorg.conf.d/00-keyboard.conf
        try:
            for file_ in self.target.fs.path("/etc/X11/xorg.conf.d/").glob("*-keyboard.conf"):
                for line in file_.open("rt"):
                    for x in XKB:
                        if x in line.upper():
                            k[x.replace("XKB", "")] = (
                                line.lower().replace('"', "").replace("option " + x.lower(), "").strip()
                            )

                yield UnixKeyboardRecord(
                    layout=k["LAYOUT"],
                    model=k["MODEL"],
                    variant=k["VARIANT"],
                    options=k["OPTIONS"],
                    backspace=k["BACKSPACE"],
                    _target=self.target,
                )
        except FileNotFoundError:
            pass

        # TODO
        # /etc/sysconfig/keyboard
        # /usr/share/kbd/keymaps/*
        # /usr/local/share/kbd/keymaps/*
