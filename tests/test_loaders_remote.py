import pytest
import socket
import ssl

from unittest.mock import patch, MagicMock, call


from dissect.target.loaders.remote import RemoteLoader, RemoteStreamConnection, RemoteStream


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
    rsc = RemoteStreamConnection("remote://127.0.0.1", 9001)
    assert rsc.is_connected() is False
    rsc.connect()
    rsc._ssl_sock.recv = MagicMock(return_value=b"ABC")
    rs = RemoteStream(rsc, 0, 3)
    rs.seek(1)
    rs.read(2)
    rs.close()
    mock_socket_class.assert_called_with(socket.AddressFamily.AF_INET, socket.SocketKind.SOCK_STREAM)
    expected = [
        call(ssl.PROTOCOL_TLSv1_2),
        call().load_default_certs(),
        call().wrap_socket(rsc._socket, server_hostname="remote://127.0.0.1"),
        call().wrap_socket().connect(("remote://127.0.0.1", 9001)),
        call().wrap_socket().send(b"2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"),
        call().wrap_socket().recv(3),
    ]
    assert mock_context.mock_calls == expected
    assert rs.tell() == 3
    assert rsc.is_connected() is True
