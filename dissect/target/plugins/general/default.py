from dissect.target.helpers.record import EmptyRecord
from dissect.target.plugin import OSPlugin, export


class DefaultPlugin(OSPlugin):
    def __init__(self, target):
        super().__init__(target)
        if len(target.filesystems) == 1:
            target.fs.mount("/", target.filesystems[0])
        else:
            for i, fs in enumerate(target.filesystems):
                target.fs.mount(f"fs{i}", fs)

    @classmethod
    def detect(cls, target):
        pass

    @classmethod
    def create(cls, target, sysvol):
        if sysvol:
            target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self):
        pass

    @export(property=True)
    def ips(self):
        return []

    @export(property=True)
    def version(self):
        pass

    @export(record=EmptyRecord)
    def users(self):
        yield from ()

    @export(property=True)
    def os(self):
        return "default"
