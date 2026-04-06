"""TCP port scanning - SYN and Connect methods."""

from __future__ import annotations

import logging
import socket
from typing import Any

from scapy.all import ICMP, IP, TCP, sr1

from netscout.scanner.base import Scanner

logger = logging.getLogger(__name__)

WELL_KNOWN_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


def _get_service(port: int) -> str:
    """Get service name for a port number."""
    return WELL_KNOWN_SERVICES.get(port, "unknown")


class TCPSynScanner(Scanner):
    """SYN stealth scan using raw packets (requires root)."""

    def scan(self, target: str, ports: list[int], *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        """Send SYN packets and analyze responses."""
        results = []

        for port in ports:
            try:
                packet = IP(dst=target) / TCP(dport=port, flags="S")
                response = sr1(packet, timeout=self.timeout, verbose=False)

                if response is None:
                    continue

                if response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)
                    if tcp_layer.flags == 0x12:  # SYN-ACK
                        results.append({
                            "port": port,
                            "state": "open",
                            "service": _get_service(port),
                        })
                        send_rst = IP(dst=target) / TCP(
                            dport=port, sport=tcp_layer.sport, flags="R" # sport instead of dport
                        )
                        sr1(send_rst, timeout=1, verbose=False)
                    elif tcp_layer.flags == 0x14:  # RST-ACK
                        pass
                elif response.haslayer(ICMP):
                    pass

            except Exception as e:
                logger.debug(f"SYN scan error on port {port}: {e}")
                continue

        logger.info(f"SYN scan found {len(results)} open ports on {target}")
        return results


class TCPConnectScanner(Scanner):
    """Full TCP connect scan (no root required)."""

    def scan(self, target: str, ports: list[int], *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        """Attempt full TCP connections."""
        results = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))

                if result == 0:
                    results.append({
                        "port": port,
                        "state": "open",
                        "service": _get_service(port),
                    })

                sock.close()

            except socket.timeout:
                continue
            except OSError as e:
                logger.debug(f"Connect scan error on port {port}: {e}")
                continue

        logger.info(f"Connect scan found {len(results)} open ports on {target}")
        return results
