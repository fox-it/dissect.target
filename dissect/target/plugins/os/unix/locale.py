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

        return

    @export(property=True)
    def language(self):
        """
        Get the configured locale(s) of the system.
        """
        locale_paths = ["/etc/default/locale", "/etc/locale.conf"]

        for locale_path in locale_paths:
            if (path := self.target.fs.path(local_path)).exists():
                for line in path.open("rt"):
                    if "LANG=" in line:
                        return line.replace("LANG=", "").replace('"', "").strip()
                return

    @export(record=UnixKeyboardRecord)
    def keyboard(self):
        """
        Get the keyboard layout(s) of the system.
        """

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
                # note that you might still want to exit if LAYOUT is not None. Add if appropriate 

        # TODO
        # /etc/sysconfig/keyboard
        # /usr/share/kbd/keymaps/*
        # /usr/local/share/kbd/keymaps/*
