import datetime

from dissect.target.plugin import Plugin, export


class GenericPlugin(Plugin):
    def check_compatible(self):
        pass

    @export(property=True)
    def activity(self):
        """Return last seen activity based on filesystem timestamps."""
        var_log = self.target.fs.path("/var/log")
        if not var_log.exists():
            return

        last_seen = 0
        for f in var_log.iterdir():
            if f.stat().st_mtime > last_seen:
                last_seen = f.stat().st_mtime

        if last_seen != 0:
            return datetime.datetime.fromtimestamp(last_seen)

        return
