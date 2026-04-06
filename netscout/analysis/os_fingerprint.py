"""TTL-based OS fingerprinting."""

from __future__ import annotations

import logging
import socket

from scapy.all import ICMP, IP, sr1

logger = logging.getLogger(__name__)

TTL_RANGES = [
    {"os": "Linux/Unix", "initial_ttl": 64, "confidence": 0.7},
    {"os": "Windows", "initial_ttl": 128, "confidence": 0.7},
    {"os": "macOS/FreeBSD", "initial_ttl": 255, "confidence": 0.6},
    {"os": "Cisco IOS", "initial_ttl": 255, "confidence": 0.5},
    {"os": "Solaris", "initial_ttl": 254, "confidence": 0.5},
]


class OSFingerprint:
    """Detect operating system using TTL analysis."""

    def detect(self, target: str) -> dict[str, str | float]:
        """Detect OS by analyzing TTL in ICMP/TCP responses.

        Args:
            target: Target IP or hostname.

        Returns:
            Dict with 'os', 'confidence', and 'ttl' keys.
        """
        ttl = self._get_ttl(target)

        if ttl is None:
            return {"os": "unknown", "confidence": 0.0, "ttl": "N/A"}

        os_guess = self._classify_ttl(ttl)

        return {
            "os": os_guess["os"],
            "confidence": os_guess["confidence"],
            "ttl": ttl,
        }

    def _get_ttl(self, target: str) -> int | None:
        """Get TTL from ICMP echo reply."""
        try:
            packet = IP(dst=target) / ICMP()
            response = sr1(packet, timeout=3, verbose=False)

            if response and response.haslayer(IP):
                return response.getlayer(IP).ttl

            return None

        except Exception as e:
            logger.debug(f"TTL detection failed for {target}: {e}")
            return None

    def _classify_ttl(self, ttl: int) -> dict[str, str | float]:
        """Classify OS based on observed TTL value."""
        best_match = {"os": "unknown", "confidence": 0.0}

        for os_info in TTL_RANGES:
            initial_ttl = os_info["initial_ttl"]
            hops = initial_ttl - ttl

            if 0 <= hops <= 32:
                return {
                    "os": os_info["os"],
                    "confidence": os_info["confidence"],
                }

        return best_match
