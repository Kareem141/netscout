"""ICMP ping sweep for host discovery."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from scapy.all import ICMP, IP, sr

from netscout.scanner.base import Scanner

logger = logging.getLogger(__name__)


class ICMPSweep(Scanner):
    """Discover hosts using ICMP Echo Request (ping sweep)."""

    def __init__(self, timeout: float = 3.0) -> None:
        super().__init__(timeout=timeout)

    def _get_ips(self, target: str) -> list[str]:
        """Get list of IPs from target."""
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            return hosts[:254]
        except ValueError:
            return [target]

    def scan(self, target: str, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        """Send ICMP Echo Requests and collect replies.

        Args:
            target: IP address or CIDR range.

        Returns:
            List of dicts with 'ip' and 'ttl' keys.
        """
        ips = self._get_ips(target)
        logger.info(f"Starting ICMP sweep on {len(ips)} hosts")

        try:
            packets = IP(dst=ips) / ICMP()
            answered, unanswered = sr(
                packets, timeout=self.timeout, verbose=False
            )

            results = []
            for sent, received in answered:
                results.append({
                    "ip": received.src,
                    "ttl": received.ttl,
                })

            logger.info(f"ICMP sweep found {len(results)} hosts")
            return results

        except Exception as e:
            logger.error(f"ICMP sweep failed: {e}")
            return []
