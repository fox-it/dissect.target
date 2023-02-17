import socket
import ssl
from unittest.mock import MagicMock, call, patch

from dissect.target.loaders.remote import RemoteStream, RemoteStreamConnection


@patch.object(ssl, "SSLContext", autospec=True)
@patch.object(socket, "socket", autospec=True)
def test_remote_loader_stream(mock_socket_class: MagicMock, mock_context: MagicMock) -> None:
    rsc = RemoteStreamConnection("remote://127.0.0.1", 9001, options={"ca": "A", "key": "B", "crt": "C"})
    assert rsc.is_connected() is False
    rsc.connect()
    rsc._ssl_sock.recv = MagicMock(return_value=b"ABC")
    rs = RemoteStream(rsc, 0, 3)
    rs.align = 1
    rs.seek(1)
    rs.read(2)
    rs.close()
    mock_socket_class.assert_called_with(socket.AddressFamily.AF_INET, socket.SocketKind.SOCK_STREAM)
    expected = [
        call(ssl.PROTOCOL_TLSv1_2),
        call().load_default_certs(),
        call().load_cert_chain(certfile="C", keyfile="B"),
        call().load_verify_locations("A"),
        call().wrap_socket(rsc._socket, server_hostname="remote://127.0.0.1"),
        call().wrap_socket().connect(("remote://127.0.0.1", 9001)),
        call().wrap_socket().send(b"2\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02"),
        call().wrap_socket().recv(2),
    ]
    assert mock_context.mock_calls == expected
    assert rs.tell() == 3
    assert rsc.is_connected() is True


@patch.object(ssl, "SSLContext", autospec=False)
@patch.object(socket, "socket", autospec=True)
def test_remote_loader_stream_embedded(mock_socket_class: MagicMock, mock_context: MagicMock) -> None:
    RemoteStreamConnection.configure("K", "C")
    RemoteStreamConnection("remote://127.0.0.1", 9001)
    mock_context.assert_has_calls([call().load_cert_chain_str(certfile="C", keyfile="K")])
