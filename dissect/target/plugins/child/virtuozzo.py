from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin


class VirtuozzoTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from Virtuozzo container's root.

    Virtuozzo conatiners are by default registered in the folder ``vz/root/$VEID``,
    where VEID will be substituted with the actual container UUID.

    /
      etc/
      var/
      vz/
          root/
              <container-uuid>/
              <container-uuid>/

    Sources:
        - https://docs.virtuozzo.com/virtuozzo_hybrid_server_7_command_line_reference/managing-system/configuration-files.html
    """

    __type__ = "virtuozzo"

    PATH = "/vz/root"

    def __init__(self, target):
        super().__init__(target)
        self.vz_containers = [p for p in self.target.fs.iterdir(self.PATH)]

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.PATH).exists():
            raise UnsupportedPluginError("No /vz/root folder found")

    def list_children(self):
        for container in self.vz_containers:
            yield ChildTargetRecord(
                type=self.__type__, 
                path=str(self.target.fs.path(self.PATH).joinpath(container)), 
                _target=self.target
            )
