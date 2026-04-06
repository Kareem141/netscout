"""Tests for JSON export."""

import json

from netscout.output.json_export import export_json
from netscout.output.models import HostResult, PortResult, ScanResult


class TestExportJSON:
    def test_export_basic(self):
        result = ScanResult(target="192.168.1.1")
        json_str = export_json(result)
        data = json.loads(json_str)

        assert data["target"] == "192.168.1.1"
        assert data["hosts"] == []

    def test_export_with_hosts(self):
        result = ScanResult(
            target="192.168.1.1",
            hosts=[
                HostResult(
                    ip="192.168.1.1",
                    mac="00:11:22:33:44:55",
                    vendor="Cisco",
                    ports=[
                        PortResult(port=80, state="open", service="http"),
                    ],
                )
            ],
        )
        json_str = export_json(result)
        data = json.loads(json_str)

        assert len(data["hosts"]) == 1
        assert data["hosts"][0]["ip"] == "192.168.1.1"
        assert len(data["hosts"][0]["ports"]) == 1

    def test_export_pretty(self):
        result = ScanResult(target="192.168.1.1")
        json_str = export_json(result, pretty=True)
        assert "\n" in json_str

    def test_export_compact(self):
        result = ScanResult(target="192.168.1.1")
        json_str = export_json(result, pretty=False)
        assert "\n" not in json_str
