"""Service banner grabbing for open ports."""

from __future__ import annotations

import logging
import socket

logger = logging.getLogger(__name__)

BANNER_PROBES = {
    21: b"USER anonymous\r\n",
    22: b"",
    23: b"\r\n",
    25: b"EHLO netscout\r\n",
    53: b"",
    80: b"GET / HTTP/1.0\r\n\r\n",
    110: b"USER test\r\n",
    143: b"a001 CAPABILITY\r\n",
    443: b"",
    993: b"",
    995: b"",
    3306: b"",
    5432: b"",
    6379: b"INFO\r\n",
    8080: b"GET / HTTP/1.0\r\n\r\n",
    8443: b"",
    9200: b"GET / HTTP/1.0\r\n\r\n",
}


class BannerGrab:
    """Grab service banners from open ports."""

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    def grab(self, host: str, port: int) -> str:
        """Attempt to grab a banner from the given host:port.

        Args:
            host: Target IP or hostname.
            port: Target port number.

        Returns:
            Banner string, or empty string on failure.
        """
        probe = BANNER_PROBES.get(port, b"")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            if probe:
                sock.sendall(probe)

            banner = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    banner += chunk
                    if len(banner) > 2048:
                        break
            except socket.timeout:
                pass

            sock.close()

            if banner:
                text = banner.decode("utf-8", errors="replace").strip()
                return text[:200]

            return ""

        except (socket.timeout, socket.error, OSError) as e:
            logger.debug(f"Banner grab failed on {host}:{port}: {e}")
            return ""
