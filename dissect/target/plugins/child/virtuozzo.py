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
    """  # noqa: E501

    __type__ = "virtuozzo"

    PATH = "/vz/root"

    def check_compatible(self) -> bool:
        return self.target.fs.path(self.PATH).exists()

    def list_children(self):
        for container in self.target.fs.path(self.PATH).iterdir():
            yield ChildTargetRecord(
                type=self.__type__,
                path=str(container),
                _target=self.target,
            )
