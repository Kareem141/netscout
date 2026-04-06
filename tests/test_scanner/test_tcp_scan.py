"""Tests for TCP port scanner."""

from unittest.mock import MagicMock, patch

from netscout.scanner.tcp_scan import TCPConnectScanner, TCPSynScanner


class TestTCPSynScanner:
    def test_init_default_timeout(self):
        scanner = TCPSynScanner()
        assert scanner.timeout == 2.0

    @patch("netscout.scanner.tcp_scan.sr1")
    def test_scan_open_port(self, mock_sr1):
        mock_response = MagicMock()
        mock_tcp = MagicMock()
        mock_tcp.flags = 0x12  # SYN-ACK
        mock_response.haslayer.return_value = True
        mock_response.getlayer.return_value = mock_tcp
        mock_sr1.return_value = mock_response

        scanner = TCPSynScanner()
        results = scanner.scan("192.168.1.1", [80])

        assert len(results) == 1
        assert results[0]["port"] == 80
        assert results[0]["state"] == "open"

    @patch("netscout.scanner.tcp_scan.sr1")
    def test_scan_closed_port(self, mock_sr1):
        mock_response = MagicMock()
        mock_tcp = MagicMock()
        mock_tcp.flags = 0x14  # RST-ACK
        mock_response.haslayer.return_value = True
        mock_response.getlayer.return_value = mock_tcp
        mock_sr1.return_value = mock_response

        scanner = TCPSynScanner()
        results = scanner.scan("192.168.1.1", [80])

        assert results == []

    @patch("netscout.scanner.tcp_scan.sr1")
    def test_scan_no_response(self, mock_sr1):
        mock_sr1.return_value = None

        scanner = TCPSynScanner()
        results = scanner.scan("192.168.1.1", [80])

        assert results == []


class TestTCPConnectScanner:
    def test_init_default_timeout(self):
        scanner = TCPConnectScanner()
        assert scanner.timeout == 2.0

    @patch("socket.socket")
    def test_scan_open_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        scanner = TCPConnectScanner()
        results = scanner.scan("192.168.1.1", [80])

        assert len(results) == 1
        assert results[0]["port"] == 80
        assert results[0]["state"] == "open"

    @patch("socket.socket")
    def test_scan_closed_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # Connection refused
        mock_socket_cls.return_value = mock_sock

        scanner = TCPConnectScanner()
        results = scanner.scan("192.168.1.1", [80])

        assert results == []

    @patch("socket.socket")
    def test_scan_timeout(self, mock_socket_cls):
        import socket
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout()
        mock_socket_cls.return_value = mock_sock

        scanner = TCPConnectScanner()
        results = scanner.scan("192.168.1.1", [80])

        assert results == []
