"""Tests for banner grabbing."""

from unittest.mock import MagicMock, patch

from netscout.scanner.banner_grab import BannerGrab


class TestBannerGrab:
    def test_init_default_timeout(self):
        grabber = BannerGrab()
        assert grabber.timeout == 3.0

    @patch("netscout.scanner.banner_grab.socket.socket")
    def test_grab_banner_http(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\n\r\n"
        mock_socket_cls.return_value = mock_sock

        grabber = BannerGrab()
        banner = grabber.grab("192.168.1.1", 80)

        assert "HTTP/1.1 200 OK" in banner
        assert "Apache/2.4" in banner

    @patch("netscout.scanner.banner_grab.socket.socket")
    def test_grab_banner_ssh(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_socket_cls.return_value = mock_sock

        grabber = BannerGrab()
        banner = grabber.grab("192.168.1.1", 22)

        assert "SSH-2.0-OpenSSH_8.9" in banner

    @patch("netscout.scanner.banner_grab.socket.socket")
    def test_grab_connection_refused(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        mock_socket_cls.return_value = mock_sock

        grabber = BannerGrab()
        banner = grabber.grab("192.168.1.1", 80)

        assert banner == ""

    @patch("netscout.scanner.banner_grab.socket.socket")
    def test_grab_timeout(self, mock_socket_cls):
        import socket
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout()
        mock_socket_cls.return_value = mock_sock

        grabber = BannerGrab()
        banner = grabber.grab("192.168.1.1", 80)

        assert banner == ""

    @patch("netscout.scanner.banner_grab.socket.socket")
    def test_grab_empty_response(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        mock_socket_cls.return_value = mock_sock

        grabber = BannerGrab()
        banner = grabber.grab("192.168.1.1", 80)

        assert banner == ""

    @patch("netscout.scanner.banner_grab.socket.socket")
    def test_grab_truncates_long_banner(self, mock_socket_cls):
        mock_sock = MagicMock()
        long_banner = b"A" * 300
        mock_sock.recv.return_value = long_banner
        mock_socket_cls.return_value = mock_sock

        grabber = BannerGrab()
        banner = grabber.grab("192.168.1.1", 80)

        assert len(banner) <= 200
