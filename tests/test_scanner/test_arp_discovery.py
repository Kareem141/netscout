"""Tests for ARP discovery scanner."""

from unittest.mock import MagicMock, patch

import pytest

from netscout.scanner.arp_discovery import ARPDiscovery


class TestARPDiscovery:
    def test_init_default_timeout(self):
        scanner = ARPDiscovery()
        assert scanner.timeout == 3.0

    def test_init_custom_timeout(self):
        scanner = ARPDiscovery(timeout=5.0)
        assert scanner.timeout == 5.0

    @patch("netscout.scanner.arp_discovery.srp")
    def test_scan_returns_hosts(self, mock_srp, mock_arp_result):
        mock_response = MagicMock()
        mock_sent = MagicMock()
        mock_received = MagicMock()
        mock_received.psrc = "192.168.1.1"
        mock_received.hwsrc = "00:11:22:33:44:55"
        mock_srp.return_value = ([(mock_sent, mock_received)], [])

        scanner = ARPDiscovery()
        results = scanner.scan("192.168.1.0/24")

        assert len(results) == 1
        assert results[0]["ip"] == "192.168.1.1"
        assert results[0]["mac"] == "00:11:22:33:44:55"

    @patch("netscout.scanner.arp_discovery.srp")
    def test_scan_empty_results(self, mock_srp):
        mock_srp.return_value = ([], [])

        scanner = ARPDiscovery()
        results = scanner.scan("192.168.1.0/24")

        assert results == []

    @patch("netscout.scanner.arp_discovery.srp")
    def test_scan_permission_error(self, mock_srp):
        mock_srp.side_effect = PermissionError("Operation not permitted")

        scanner = ARPDiscovery()
        with pytest.raises(PermissionError):
            scanner.scan("192.168.1.0/24")

    @patch("netscout.scanner.arp_discovery.srp")
    def test_scan_generic_exception_returns_empty(self, mock_srp):
        mock_srp.side_effect = Exception("Network error")

        scanner = ARPDiscovery()
        results = scanner.scan("192.168.1.0/24")

        assert results == []
