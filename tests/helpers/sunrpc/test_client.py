from unittest.mock import MagicMock, patch
import pytest
from dissect.target.helpers.nfs.nfs import FileHandle3, MountOK
from dissect.target.helpers.nfs.serializer import MountResultDeserializer
from dissect.target.helpers.sunrpc import sunrpc
from dissect.target.helpers.sunrpc.client import Client, auth_null
from dissect.target.helpers.sunrpc.serializer import PortMappingSerializer, StringSerializer, UInt32Serializer
from dissect.target.helpers.sunrpc.sunrpc import PortMapping


@pytest.fixture
def mock_socket():
    with patch("socket.socket") as mock_socket:
        yield mock_socket


def test_portmap_call(mock_socket) -> None:
    portmap_request = b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x86\xa3\x00\x00\x00\x03\x00\x00\x00\x06\x00\x00\x00\x00'  # noqa: E501

    portmap_response = b'\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x01'  # noqa: E501

    # Mock the socket instance
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance

    client = Client.connectPortMapper("localhost")

    # Prepare the portmap request and response
    portmap_params = PortMapping(program=100003, version=3, protocol=sunrpc.Protocol.TCP)

    # Set up the mock to return the response payload
    portmap_response_fragment_header = (len(portmap_response) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.recv.side_effect = [portmap_response_fragment_header, portmap_response]

    result = client.call(100000, 2, 3, portmap_params, PortMappingSerializer(), UInt32Serializer())

    # Verify that the request payload was sent
    portmap_request_fragment_header = (len(portmap_request) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.sendall.assert_called_with(portmap_request_fragment_header + portmap_request)

    # Verify that the result of the call equals the portmap_result variable
    assert result == 2049


def test_mount_call(mock_socket) -> None:
    mount_request = b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa5\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n/home/roel\x00\x00'  # noqa: E501

    mount_response = b'\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x01\x00\x07\x00\x02\x00\xec\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4\x00\x00\x00\x01\x00\x00\x00\x01'  # noqa: E501

    # Mock the socket instance
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance

    # Set up the mock to return the response payload
    portmap_response_fragment_header = (len(mount_response) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.recv.side_effect = [portmap_response_fragment_header, mount_response]

    mount_client = Client.connect("localhost", 2049, auth_null())
    result = mount_client.call(
        100005, 3, 1, "/home/roel", StringSerializer(), MountResultDeserializer()
    )

    # Verify that the request payload was sent
    portmap_request_fragment_header = (len(mount_request) | 0x80000000).to_bytes(4, "big")
    mock_sock_instance.sendall.assert_called_with(portmap_request_fragment_header + mount_request)

    # Verify that the result of the call equals the mount_result variable
    assert result == MountOK(filehandle=FileHandle3(opaque=b'\x01\x00\x07\x00\x02\x00\xec\x02\x00\x00\x00\x00\xb5g\x131&\xf1I\xed\xb8R\rx\\h8\xb4'), authFlavors=[1])  # noqa: E501


