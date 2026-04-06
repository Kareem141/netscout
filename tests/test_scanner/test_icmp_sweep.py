"""Tests for ICMP sweep scanner."""

from unittest.mock import MagicMock, patch

from netscout.scanner.icmp_sweep import ICMPSweep


class TestICMPSweep:
    def test_init_default_timeout(self):
        scanner = ICMPSweep()
        assert scanner.timeout == 3.0

    def test_get_ips_from_cidr(self):
        scanner = ICMPSweep()
        ips = scanner._get_ips("192.168.1.0/30")
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    def test_get_ips_from_single_ip(self):
        scanner = ICMPSweep()
        ips = scanner._get_ips("10.0.0.1")
        assert ips == ["10.0.0.1"]

    @patch("netscout.scanner.icmp_sweep.sr")
    def test_scan_returns_hosts(self, mock_sr):
        mock_sent = MagicMock()
        mock_received = MagicMock()
        mock_received.src = "192.168.1.1"
        mock_received.ttl = 64
        mock_sr.return_value = ([(mock_sent, mock_received)], [])

        scanner = ICMPSweep()
        results = scanner.scan("192.168.1.1")

        assert len(results) == 1
        assert results[0]["ip"] == "192.168.1.1"
        assert results[0]["ttl"] == 64

    @patch("netscout.scanner.icmp_sweep.sr")
    def test_scan_empty_results(self, mock_sr):
        mock_sr.return_value = ([], [])

        scanner = ICMPSweep()
        results = scanner.scan("192.168.1.0/24")

        assert results == []

    @patch("netscout.scanner.icmp_sweep.sr")
    def test_scan_exception_returns_empty(self, mock_sr):
        mock_sr.side_effect = Exception("Network error")

        scanner = ICMPSweep()
        results = scanner.scan("192.168.1.1")

        assert results == []
