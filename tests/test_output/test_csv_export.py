"""Tests for CSV export."""

from netscout.output.csv_export import export_csv
from netscout.output.models import HostResult, PortResult, ScanResult


class TestExportCSV:
    def test_export_basic(self):
        result = ScanResult(target="192.168.1.1")
        csv_str = export_csv(result)

        assert "host_ip" in csv_str
        assert "port" in csv_str
        assert "state" in csv_str

    def test_export_with_hosts_and_ports(self):
        result = ScanResult(
            target="192.168.1.1",
            hosts=[
                HostResult(
                    ip="192.168.1.1",
                    mac="00:11:22:33:44:55",
                    vendor="Cisco",
                    ports=[
                        PortResult(port=80, state="open", service="http"),
                        PortResult(port=443, state="open", service="https"),
                    ],
                )
            ],
        )
        csv_str = export_csv(result)
        lines = csv_str.strip().split("\n")

        # Header + 2 port rows
        assert len(lines) == 3
        assert "192.168.1.1" in lines[1]
        assert "80" in lines[1]
        assert "443" in lines[2]

    def test_export_host_without_ports(self):
        result = ScanResult(
            target="192.168.1.1",
            hosts=[HostResult(ip="192.168.1.1")],
        )
        csv_str = export_csv(result)
        lines = csv_str.strip().split("\n")

        # Header + 1 host row (no ports)
        assert len(lines) == 2
        assert "no ports scanned" in lines[1]

    def test_export_with_special_characters(self):
        result = ScanResult(
            target="192.168.1.1",
            hosts=[
                HostResult(
                    ip="192.168.1.1",
                    ports=[
                        PortResult(
                            port=80,
                            state="open",
                            service="http",
                            banner='Server: "Apache/2.4" (Ubuntu)',
                        ),
                    ],
                )
            ],
        )
        csv_str = export_csv(result)

        # CSV should properly escape quotes
        assert "Apache/2.4" in csv_str
