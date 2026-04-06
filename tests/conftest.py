"""Shared test fixtures for NetScout tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_arp_result():
    """Return a mock ARP discovery result."""
    return [
        {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
        {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:FF"},
        {"ip": "192.168.1.3", "mac": "11:22:33:44:55:66"},
    ]


@pytest.fixture
def mock_icmp_result():
    """Return a mock ICMP sweep result."""
    return [
        {"ip": "10.0.0.1", "ttl": 64},
        {"ip": "10.0.0.2", "ttl": 128},
        {"ip": "10.0.0.5", "ttl": 255},
    ]


@pytest.fixture
def mock_port_result():
    """Return a mock port scan result."""
    return [
        {"port": 22, "state": "open", "service": "ssh", "banner": "SSH-2.0-OpenSSH_8.9"},
        {"port": 80, "state": "open", "service": "http", "banner": "HTTP/1.1 200 OK"},
        {"port": 443, "state": "open", "service": "https", "banner": ""},
        {"port": 8080, "state": "filtered", "service": "unknown", "banner": ""},
        {"port": 3306, "state": "closed", "service": "mysql", "banner": ""},
    ]


@pytest.fixture
def mock_host_result(mock_port_result):
    """Return a mock host result with ports."""
    return {
        "ip": "192.168.1.1",
        "mac": "00:11:22:33:44:55",
        "vendor": "Cisco",
        "os_guess": "Linux",
        "os_confidence": 0.75,
        "ports": mock_port_result,
    }


@pytest.fixture
def mock_scan_result(mock_host_result):
    """Return a complete mock scan result."""
    return {
        "target": "192.168.1.0/24",
        "hosts": [mock_host_result],
        "total_ports_scanned": 1000,
        "total_open_ports": 3,
        "duration_seconds": 15.5,
    }


@pytest.fixture
def mock_scapy_arp():
    """Mock Scapy arping function."""
    mock = MagicMock()
    mock.return_value = (
        [
            (MagicMock(payload=MagicMock(psrc="192.168.1.1", hwsrc="00:11:22:33:44:55")), None),
            (MagicMock(payload=MagicMock(psrc="192.168.1.2", hwsrc="AA:BB:CC:DD:EE:FF")), None),
        ],
        [],
    )
    return mock


@pytest.fixture
def mock_scapy_sr():
    """Mock Scapy sr() function for ICMP/TCP."""
    mock = MagicMock()
    mock.return_value = (
        [
            (
                MagicMock(payload=MagicMock(dst="192.168.1.1")),
                MagicMock(payload=MagicMock(src="192.168.1.1", ttl=64)),
            ),
        ],
        [],
    )
    return mock
