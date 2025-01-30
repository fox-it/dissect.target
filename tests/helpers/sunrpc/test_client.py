from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dissect.target.helpers.nfs.mount_client import Client as MountClient
from dissect.target.helpers.nfs.nfs3 import (
    EntryPlus3,
    FileAttributes3,
    FileHandle3,
    FileType3,
    Lookup3resok,
    MountOK3,
    NfsTime3,
    SpecData3,
)
from dissect.target.helpers.nfs.nfs_client import Client as NfsClient
from dissect.target.helpers.nfs.nfs_client import ReadDirResult
from dissect.target.helpers.sunrpc import sunrpc
from dissect.target.helpers.sunrpc.client import Client, auth_unix
from dissect.target.helpers.sunrpc.serializer import (
    PortMappingSerializer,
    UInt32Serializer,
)
from dissect.target.helpers.sunrpc.sunrpc import GetPortProc, PortMapping


@pytest.fixture
def mock_socket():
    with patch("socket.socket") as mock_socket:
        yield mock_socket


def test_portmap_call(mock_socket: MagicMock) -> None:
    portmap_request = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x86\xa3\x00\x00\x00\x03\x00\x00\x00\x06\x00\x00\x00\x00"  # noqa: E501

    portmap_response = b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x01"  # noqa: E501

    # Mock the socket instance
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance

    client = Client.connect_port_mapper("localhost")

    # Prepare the portmap request and response
    portmap_params = PortMapping(program=100003, version=3, protocol=sunrpc.Protocol.TCP)

    # Set up the mock to return the response payload
    response_fragment_header = (len(portmap_response) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.recv.side_effect = [response_fragment_header, portmap_response]

    result = client.call(GetPortProc, portmap_params, PortMappingSerializer(), UInt32Serializer())

    # Verify that the request payload was sent
    portmap_request_fragment_header = (len(portmap_request) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.sendall.assert_called_with(portmap_request_fragment_header + portmap_request)

    # Verify that the result of the call equals the portmap_result variable
    assert result == 2049


def test_mount_call(mock_socket: MagicMock) -> None:
    mount_request = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa5\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n/home/roel\x00\x00"  # noqa: E501

    mount_response = b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x01\x00\x07\x00\x02\x00\xec\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4\x00\x00\x00\x01\x00\x00\x00\x01"  # noqa: E501

    # Mock the socket instance
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance

    # Set up the mock to return the response payload
    mount_response_fragment_header = (len(mount_response) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.recv.side_effect = [mount_response_fragment_header, mount_response]

    mount_client = MountClient.connect("localhost", 2049)
    result = mount_client.mount("/home/roel")

    # Verify that the request payload was sent
    portmap_request_fragment_header = (len(mount_request) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.sendall.assert_called_with(portmap_request_fragment_header + mount_request)

    # Verify that the result of the call equals the mount_result variable
    assert result == MountOK3(
        filehandle=FileHandle3(
            opaque=b"\x01\x00\x07\x00\x02\x00\xec\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4"
        ),
        auth_flavors=[1],
    )


def test_readdir(mock_socket: MagicMock) -> None:
    readdir_request = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa3\x00\x00\x00\x03\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x1cq\xd5\x93D\x00\x00\x00\x07twigtop\x00\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x01\x00\x07\x00\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x80\x00"  # noqa: E501
    readdir_response = b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x01\xfd\x00\x00\x00\x02\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00Yq\x99zI\x1e5\r\x00\x00\x00\x00\x02\xee&\xdag\x8ar\xba)\xd7\xba.g\x8ar\x96\x18\xd7\x91<g\x8ar\x96\x18\xd7\x91<\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x02\xee\x84\x19\x00\x00\x00\x08test.txt>z;\x99\x07@\x9c_\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x01\xb4\x00\x00\x00\x01\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00Yq\x99zI\x1e5\r\x00\x00\x00\x00\x02\xee\x84\x19g\x8aqk\r\xa4\xb7\x8eg\x8aqg\x11\x93h\xf9g\x8aqg\x11\x93h\xf9\x00\x00\x00\x01\x00\x00\x00$\x01\x00\x07\x01\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4\x19\x84\xee\x02\xc1\x8a\x8c\\\x00\x00\x00\x01\x00\x00\x00\x00\x02\xee&\xda\x00\x00\x00\x01.\x00\x00\x00CjR\xafoN\x82\xf0\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x01\xfd\x00\x00\x00\x02\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00Yq\x99zI\x1e5\r\x00\x00\x00\x00\x02\xee&\xdag\x8ar\xba)\xd7\xba.g\x8ar\x96\x18\xd7\x91<g\x8ar\x96\x18\xd7\x91<\x00\x00\x00\x01\x00\x00\x00\x1c\x01\x00\x07\x00\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4\x00\x00\x00\x01\x00\x00\x00\x00\x02\xee\x84\x07\x00\x00\x00\ttest2.txt\x00\x00\x00hF\x10\xd4\xd7u\xe2>\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x01\xb4\x00\x00\x00\x01\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00Yq\x99zI\x1e5\r\x00\x00\x00\x00\x02\xee\x84\x07g\x8ar\x96\x18\xd7\x91<g\x8ar\x9e+\x9e\xde\ng\x8ar\x9e+\x9e\xde\n\x00\x00\x00\x01\x00\x00\x00$\x01\x00\x07\x01\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4\x07\x84\xee\x02\x9524*\x00\x00\x00\x01\x00\x00\x00\x00\x02\xec\x00\x02\x00\x00\x00\x02..\x00\x00\x7f\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"  # noqa: E501

    # Mock the socket instance
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance

    # Set up the mock to return the response payload
    readdir_response_fragment_header = (len(readdir_response) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.recv.side_effect = [readdir_response_fragment_header, readdir_response]

    auth = auth_unix("twigtop", 1000, 1000, [])
    auth.credentials.stamp = 1909822276
    nfs_client = NfsClient.connect("localhost", 2049, auth, 666)
    result = nfs_client.readdir(
        FileHandle3(opaque=b"\x01\x00\x07\x00\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4")
    )

    # Verify that the request payload was sent
    readdir_request_header = (len(readdir_request) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.sendall.assert_called_with(readdir_request_header + readdir_request)

    # Verify that the result of the call equals the readdir_result variable
    assert result == ReadDirResult(
        dir_attributes=FileAttributes3(
            type=FileType3.DIR,
            mode=509,
            nlink=2,
            uid=1000,
            gid=1000,
            size=4096,
            used=4096,
            rdev=SpecData3(specdata1=0, specdata2=0),
            fsid=6445101292235666701,
            fileid=49161946,
            atime=NfsTime3(seconds=1737126586, nseconds=702003758),
            mtime=NfsTime3(seconds=1737126550, nseconds=416780604),
            ctime=NfsTime3(seconds=1737126550, nseconds=416780604),
        ),
        entries=[
            EntryPlus3(
                fileid=49185817,
                name="test.txt",
                cookie=4501976305947941983,
                attributes=FileAttributes3(
                    type=FileType3.REG,
                    mode=436,
                    nlink=1,
                    uid=1000,
                    gid=1000,
                    size=5,
                    used=4096,
                    rdev=SpecData3(specdata1=0, specdata2=0),
                    fsid=6445101292235666701,
                    fileid=49185817,
                    atime=NfsTime3(seconds=1737126251, nseconds=228898702),
                    mtime=NfsTime3(seconds=1737126247, nseconds=294873337),
                    ctime=NfsTime3(seconds=1737126247, nseconds=294873337),
                ),
                handle=FileHandle3(
                    opaque=b"\x01\x00\x07\x01\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4\x19\x84\xee\x02\xc1\x8a\x8c\\"  # noqa: E501
                ),
            ),
            EntryPlus3(
                fileid=49161946,
                name=".",
                cookie=4857786061512671984,
                attributes=FileAttributes3(
                    type=FileType3.DIR,
                    mode=509,
                    nlink=2,
                    uid=1000,
                    gid=1000,
                    size=4096,
                    used=4096,
                    rdev=SpecData3(specdata1=0, specdata2=0),
                    fsid=6445101292235666701,
                    fileid=49161946,
                    atime=NfsTime3(seconds=1737126586, nseconds=702003758),
                    mtime=NfsTime3(seconds=1737126550, nseconds=416780604),
                    ctime=NfsTime3(seconds=1737126550, nseconds=416780604),
                ),
                handle=FileHandle3(
                    opaque=b"\x01\x00\x07\x00\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4"
                ),
            ),
            EntryPlus3(
                fileid=49185799,
                name="test2.txt",
                cookie=7513711534648189502,
                attributes=FileAttributes3(
                    type=FileType3.REG,
                    mode=436,
                    nlink=1,
                    uid=1000,
                    gid=1000,
                    size=6,
                    used=4096,
                    rdev=SpecData3(specdata1=0, specdata2=0),
                    fsid=6445101292235666701,
                    fileid=49185799,
                    atime=NfsTime3(seconds=1737126550, nseconds=416780604),
                    mtime=NfsTime3(seconds=1737126558, nseconds=731831818),
                    ctime=NfsTime3(seconds=1737126558, nseconds=731831818),
                ),
                handle=FileHandle3(
                    opaque=b"\x01\x00\x07\x01\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4\x07\x84\xee\x02\x9524*"  # noqa: E501
                ),
            ),
            EntryPlus3(fileid=49020930, name="..", cookie=9223372036854775807, attributes=None, handle=None),
        ],
    )


def test_lookup(mock_socket: MagicMock) -> None:
    lookup_request = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa3\x00\x00\x00\x03\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x1ch \x9b-\x00\x00\x00\x07machine\x00\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x01\x00\x07\x00\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4\x00\x00\x00\x04dir1"  # noqa: E501
    lookup_response = b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x01\x00\x07\x01\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb41\x12\xf2\x02\x8f\x9958\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x01\xfd\x00\x00\x00\x03\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00Yq\x99zI\x1e5\r\x00\x00\x00\x00\x02\xf2\x121g\xabzW9\x02\xc4\xf1g\xa9\xbc\xa3.\x95\xbf\x03g\xa9\xbc\xa3.\x95\xbf\x03\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x01\xf8\x00\x00\x00\x03\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00Yq\x99zI\x1e5\r\x00\x00\x00\x00\x02\xee&\xdag\xab}\xdb#R\x98\xdeg\xa9\xe05\x142Q+g\xab{\xdc)8\xfa\xf2"  # noqa: E501

    # Mock the socket instance
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance

    # Set up the mock to return the response payload
    readdir_response_fragment_header = (len(lookup_response) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.recv.side_effect = [readdir_response_fragment_header, lookup_response]

    auth = auth_unix("machine", 1000, 1000, [])
    auth.credentials.stamp = 1746967341
    nfs_client = NfsClient.connect("localhost", 2049, auth, 666)
    parent_handle = FileHandle3(
        opaque=b"\x01\x00\x07\x00\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4"
    )
    result = nfs_client.lookup("dir1", parent_handle)

    # Verify that the request payload was sent
    readdir_request_header = (len(lookup_request) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.sendall.assert_called_with(readdir_request_header + lookup_request)

    # Verify that the result of the call equals the result
    assert result == Lookup3resok(
        object=FileHandle3(
            opaque=b"\x01\x00\x07\x01\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb41\x12\xf2\x02\x8f\x9958"  # noqa: E501
        ),
        obj_attributes=FileAttributes3(
            type=FileType3.DIR,
            mode=509,
            nlink=3,
            uid=1000,
            gid=1000,
            size=4096,
            used=4096,
            rdev=SpecData3(specdata1=0, specdata2=0),
            fsid=6445101292235666701,
            fileid=49418801,
            atime=NfsTime3(seconds=1739291223, nseconds=956482801),
            mtime=NfsTime3(seconds=1739177123, nseconds=781565699),
            ctime=NfsTime3(seconds=1739177123, nseconds=781565699),
        ),
        dir_attributes=FileAttributes3(
            type=FileType3.DIR,
            mode=504,
            nlink=3,
            uid=1000,
            gid=1000,
            size=4096,
            used=4096,
            rdev=SpecData3(specdata1=0, specdata2=0),
            fsid=6445101292235666701,
            fileid=49161946,
            atime=NfsTime3(seconds=1739292123, nseconds=592615646),
            mtime=NfsTime3(seconds=1739186229, nseconds=338841899),
            ctime=NfsTime3(seconds=1739291612, nseconds=691600114),
        ),
    )


def test_getattr(mock_socket: MagicMock) -> None:
    getattr_request = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa3\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x1c\xe3\xee-G\x00\x00\x00\x07machine\x00\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x01\x00\x07\x00\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4"  # noqa: E501
    getattr_response = b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x01\xf8\x00\x00\x00\x03\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00Yq\x99zI\x1e5\r\x00\x00\x00\x00\x02\xee&\xdag\xad\xae\xf5\x1f\x12\xc8\xecg\xa9\xe05\x142Q+g\xab{\xdc)8\xfa\xf2"  # noqa: E501

    # Mock the socket instance
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance

    # Set up the mock to return the response payload
    readdir_response_fragment_header = (len(getattr_response) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.recv.side_effect = [readdir_response_fragment_header, getattr_response]

    auth = auth_unix("machine", 1000, 1000, [])
    auth.credentials.stamp = 3824037191
    nfs_client = NfsClient.connect("localhost", 2049, auth, 666)
    file_handle = FileHandle3(
        opaque=b"\x01\x00\x07\x00\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4"
    )
    result = nfs_client.getattr(file_handle)

    # Verify that the request payload was sent
    readdir_request_header = (len(getattr_request) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.sendall.assert_called_with(readdir_request_header + getattr_request)

    # Verify that the result of the call equals the result
    assert result == FileAttributes3(
        type=FileType3.DIR,
        mode=504,
        nlink=3,
        uid=1000,
        gid=1000,
        size=4096,
        used=4096,
        rdev=SpecData3(specdata1=0, specdata2=0),
        fsid=6445101292235666701,
        fileid=49161946,
        atime=NfsTime3(seconds=1739435765, nseconds=521324780),
        mtime=NfsTime3(seconds=1739186229, nseconds=338841899),
        ctime=NfsTime3(seconds=1739291612, nseconds=691600114),
    )


def test_readlink(mock_socket: MagicMock) -> None:
    readlink_request = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa3\x00\x00\x00\x03\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00\x1ccy7\xba\x00\x00\x00\x07machine\x00\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,\x01\x00\x07\x02\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4\x0f{\xee\x02\xefoz\xef\xda&\xee\x02'/\x00\x91"  # noqa: E501
    readlink_response = b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x01\xff\x00\x00\x00\x01\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Yq\x99zI\x1e5\r\x00\x00\x00\x00\x02\xee{\x0fg\xac\xba\xc3\r5\xab\xa0g\xa9\xbe\x0c:H\x15\xc0g\xa9\xbe\x0c:H\x15\xc0\x00\x00\x00\x0edir1/dir2/dir3\x00\x00"  # noqa: E501

    # Mock the socket instance
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance

    # Set up the mock to return the response payload
    readdir_response_fragment_header = (len(readlink_response) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.recv.side_effect = [readdir_response_fragment_header, readlink_response]

    auth = auth_unix("machine", 1000, 1000, [])
    auth.credentials.stamp = 1668888506
    nfs_client = NfsClient.connect("localhost", 2049, auth, 666)
    file_handle = FileHandle3(
        opaque=b"\x01\x00\x07\x02\xda&\xee\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4\x0f{\xee\x02\xefoz\xef\xda&\xee\x02'/\x00\x91"  # noqa: E501
    )
    result = nfs_client.readlink(file_handle)

    # Verify that the request payload was sent
    readdir_request_header = (len(readlink_request) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.sendall.assert_called_with(readdir_request_header + readlink_request)

    # Verify that the result of the call equals the result
    assert result == "dir1/dir2/dir3"
