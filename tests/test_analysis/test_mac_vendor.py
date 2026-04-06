"""Tests for MAC vendor lookup."""

import os
import tempfile

from netscout.analysis.mac_vendor import MACVendor


class TestMACVendor:
    def test_lookup_known_mac(self):
        oui_content = "001122=Cisco Systems\n005056=VMware Inc\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(oui_content)
            temp_path = f.name

        try:
            vendor = MACVendor(oui_file=temp_path)
            result = vendor.lookup("00:11:22:33:44:55")
            assert result == "Cisco Systems"
        finally:
            os.unlink(temp_path)

    def test_lookup_unknown_mac(self):
        oui_content = "001122=Cisco Systems\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(oui_content)
            temp_path = f.name

        try:
            vendor = MACVendor(oui_file=temp_path)
            result = vendor.lookup("AA:BB:CC:DD:EE:FF")
            assert result == "unknown"
        finally:
            os.unlink(temp_path)

    def test_lookup_missing_file(self):
        vendor = MACVendor(oui_file="/nonexistent/path/oui.txt")
        result = vendor.lookup("00:11:22:33:44:55")
        assert result == "unknown"

    def test_normalize_mac_colons(self):
        vendor = MACVendor()
        assert vendor._normalize_mac("00:11:22:33:44:55") == "001122334455"

    def test_normalize_mac_dashes(self):
        vendor = MACVendor()
        assert vendor._normalize_mac("00-11-22-33-44-55") == "001122334455"

    def test_normalize_mac_dots(self):
        vendor = MACVendor()
        assert vendor._normalize_mac("0011.2233.4455") == "001122334455"

    def test_normalize_mac_uppercase(self):
        vendor = MACVendor()
        assert vendor._normalize_mac("aa:bb:cc:dd:ee:ff") == "AABBCCDDEEFF"
