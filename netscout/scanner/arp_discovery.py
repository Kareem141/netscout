"""ARP host discovery for LAN scanning."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from scapy.all import ARP, Ether, srp

from netscout.scanner.base import Scanner

logger = logging.getLogger(__name__)


class ARPDiscovery(Scanner):
    """Discover hosts on the local network using ARP requests."""

    def __init__(self, timeout: float = 3.0) -> None:
        super().__init__(timeout=timeout)

    def _get_network(self, target: str) -> str:
        """Extract network range from target."""
        try:
            network = ipaddress.ip_network(target, strict=False)
            return str(network)
        except ValueError:
            ip = ipaddress.ip_address(target)
            return f"{ip}/24"

    def scan(self, target: str, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        """Send ARP requests and collect responses.

        Args:
            target: IP address or CIDR range.

        Returns:
            List of dicts with 'ip' and 'mac' keys.
        """
        network = self._get_network(target)
        logger.info(f"Starting ARP discovery on {network}")

        try:
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            answered, _ = srp(packet, timeout=self.timeout, verbose=False)

            results = []
            for sent, received in answered:
                results.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                })

            logger.info(f"ARP discovery found {len(results)} hosts")
            return results

        except PermissionError:
            logger.error("ARP discovery requires root privileges")
            raise
        except Exception as e:
            logger.error(f"ARP discovery failed: {e}")
            return []
