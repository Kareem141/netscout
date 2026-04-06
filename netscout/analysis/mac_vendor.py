"""MAC vendor OUI lookup."""

from __future__ import annotations

import os
from pathlib import Path


class MACVendor:
    """Lookup MAC vendor from bundled OUI database."""

    def __init__(self, oui_file: str | None = None) -> None:
        self._oui_db: dict[str, str] = {}
        self._load_oui_file(oui_file)

    def _load_oui_file(self, oui_file: str | None = None) -> None:
        """Load OUI database from file.

        Supports two formats:
        - Wireshark manuf format: '00:00:0C\tCisco\tCisco Systems, Inc'
        - Simple key=value format: '00000C=Cisco Systems, Inc'
        """
        if oui_file is None:
            oui_file = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "data",
                "oui.txt",
            )

        if not os.path.exists(oui_file):
            return

        with open(oui_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if "=" in line:
                    prefix, vendor = line.split("=", 1)
                    self._oui_db[prefix.strip().upper()] = vendor.strip()
                elif "\t" in line:
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        raw_prefix = parts[0].strip().replace(":", "").replace("-", "").upper()
                        prefix = raw_prefix[:6]
                        vendor = parts[-1].strip()
                        if prefix and vendor:
                            self._oui_db[prefix] = vendor

    def lookup(self, mac: str) -> str:
        """Lookup vendor for a MAC address.

        Args:
            mac: MAC address in any common format.

        Returns:
            Vendor name or 'unknown'.
        """
        prefix = self._normalize_mac(mac)[:6]
        return self._oui_db.get(prefix.upper(), "unknown")

    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address to uppercase hex without separators."""
        return mac.replace(":", "").replace("-", "").replace(".", "").upper()
