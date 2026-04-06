"""Tests for output models."""

import pytest
from pydantic import ValidationError

from netscout.output.models import HostResult, PortResult, ScanResult


class TestPortResult:
    def test_defaults(self):
        port = PortResult(port=80, state="open")
        assert port.port == 80
        assert port.protocol == "tcp"
        assert port.state == "open"
        assert port.service == "unknown"
        assert port.banner == ""

    def test_full_data(self):
        port = PortResult(
            port=22,
            protocol="tcp",
            state="open",
            service="ssh",
            version="OpenSSH 8.9",
            banner="SSH-2.0-OpenSSH_8.9",
        )
        assert port.service == "ssh"
        assert port.banner == "SSH-2.0-OpenSSH_8.9"


class TestHostResult:
    def test_defaults(self):
        host = HostResult(ip="192.168.1.1")
        assert host.ip == "192.168.1.1"
        assert host.mac == ""
        assert host.vendor == "unknown"
        assert host.os_guess == "unknown"
        assert host.os_confidence == 0.0
        assert host.ports == []

    def test_with_ports(self):
        ports = [
            PortResult(port=80, state="open", service="http"),
            PortResult(port=443, state="open", service="https"),
        ]
        host = HostResult(ip="192.168.1.1", ports=ports)
        assert len(host.ports) == 2


class TestScanResult:
    def test_defaults(self):
        result = ScanResult(target="192.168.1.0/24")
        assert result.target == "192.168.1.0/24"
        assert result.hosts == []
        assert result.total_ports_scanned == 0
        assert result.total_open_ports == 0

    def test_summary(self):
        result = ScanResult(
            target="192.168.1.0/24",
            hosts=[HostResult(ip="192.168.1.1")],
            total_ports_scanned=100,
            total_open_ports=5,
            duration_seconds=10.5,
        )
        summary = result.summary
        assert summary["target"] == "192.168.1.0/24"
        assert summary["hosts_found"] == 1
        assert summary["total_ports_scanned"] == 100
        assert summary["total_open_ports"] == 5
