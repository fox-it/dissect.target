from __future__ import annotations

from io import BytesIO

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.child.esxi import ESXiChildTargetPlugin
from dissect.target.plugins.os.unix.esxi._os import ESXiPlugin
from dissect.target.target import Target


def test_esxi_children() -> None:
    """Test that the ESXi child target plugin lists children correctly."""
    vfs = VirtualFilesystem()
    vfs.map_file_fh(
        "/etc/vmware/hostd/vmInventory.xml",
        BytesIO(b"""
<ConfigRoot>
  <ConfigEntry id="0000">
    <objID>1</objID>
    <secDomain/>
    <vmxCfgPath>/vmfs/volumes/6800e48c-3dcffc58-6af7-bc2411ec8065/Alpine/Alpine.vmx</vmxCfgPath>
  </ConfigEntry>
</ConfigRoot>"""),
    )
    vfs.map_file_fh(
        "/vmfs/volumes/6800e48c-3dcffc58-6af7-bc2411ec8065/Alpine/Alpine.vmx", BytesIO(b'displayName = "Alpine"')
    )

    target = Target()
    target._os_plugin = ESXiPlugin(target)
    target.filesystems.add(vfs)
    target.fs.mount("/", vfs)
    target.apply()

    target.add_plugin(ESXiChildTargetPlugin)

    children = [child for _, child in target.list_children()]

    assert len(children) == 1

    assert children[0].type == "esxi"
    assert children[0].name == "Alpine"
    assert str(children[0].path) == "/vmfs/volumes/6800e48c-3dcffc58-6af7-bc2411ec8065/Alpine/Alpine.vmx"
