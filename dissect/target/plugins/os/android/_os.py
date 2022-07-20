from dissect.target.plugin import OSPlugin, export


class BuildProp:
    def __init__(self, fh):
        self.props = {}

        for line in fh:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            k, v = line.split("=")
            self.props[k] = v


class AndroidPlugin(OSPlugin):
    def __init__(self, target):
        super().__init__(target)
        self.target = target
        self.props = BuildProp(self.target.fs.open("/build.prop"))

    @classmethod
    def detect(cls, target):
        for fs in target.filesystems:
            if fs.exists("/build.prop"):
                return fs
        return None

    @classmethod
    def create(cls, target, sysvol):
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self):
        return self.props.props["ro.build.host"]

    @export(property=True)
    def ips(self):
        return []

    @export(property=True)
    def version(self):
        release_version = self.props.props["ro.build.version.release"]
        security_patch_version = self.props.props["ro.build.version.security_patch"]
        return f"Android {release_version} ({security_patch_version})"

    @export(property=True)
    def os(self):
        return "android"

    def users(self):
        raise NotImplementedError()
