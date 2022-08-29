import pytest
import socket
import ssl

from unittest.mock import patch, MagicMock, call


from dissect.target.loaders.remote import RemoteLoader, RemoteStream


@pytest.mark.parametrize(
    "uri, expected",
    [
        ("remote://somewhere", True),
        ("/path/to/file", False),
    ],
)
def test_remote_loader_detect(uri, expected):
    assert RemoteLoader.detect(uri) == expected


@patch.object(ssl, "SSLContext", autospec=True)
@patch.object(socket, "socket", autospec=True)
def test_remote_loader_stream(mock_socket_class, mock_context):
    rs = RemoteStream("remote://127.0.0.1:9001")
    assert rs.is_connected() is False
    rs.connect()
    rs._ssl_sock.recv = MagicMock(return_value=b"ABC")
    rs.seek(15)
    rs.read(2)
    rs.close()
    mock_socket_class.assert_called_with(socket.AddressFamily.AF_INET, socket.SocketKind.SOCK_STREAM)
    expected = [
        call(ssl.PROTOCOL_TLSv1_2),
        call().load_default_certs(),
        call().wrap_socket(rs._socket, server_hostname="127.0.0.1"),
        call().wrap_socket().connect(("127.0.0.1", 9001)),
        call().wrap_socket().send(b"\x03\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x02"),
        call().wrap_socket().recv(2),
        call().wrap_socket().send(b"c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    ]
    assert mock_context.mock_calls == expected
    assert rs.tell() == 15
    assert rs.is_connected() is True
