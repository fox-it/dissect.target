from dissect.target import Target
from dissect.target.plugins.general.config import ConfigurationTreePlugin


class EtcTree(ConfigurationTreePlugin):
    __namespace__ = "etc"

    def __init__(self, target: Target):
        super().__init__(target, "/etc")
