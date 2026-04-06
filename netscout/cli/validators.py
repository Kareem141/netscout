"""Target and input validators for CLI commands."""

from __future__ import annotations

import ipaddress
import re
import socket


def validate_ip(target: str) -> str:
    """Validate and return a single IP address."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        raise ValueError(f"Invalid IP address: {target}")


def validate_cidr(target: str) -> str:
    """Validate and return a CIDR network."""
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        raise ValueError(f"Invalid CIDR notation: {target}")


def validate_hostname(target: str) -> str:
    """Validate and optionally resolve a hostname."""
    pattern = re.compile(
        r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$"
    )
    if not pattern.match(target):
        raise ValueError(f"Invalid hostname: {target}")
    return target


def resolve_hostname(target: str) -> str:
    """Resolve a hostname to an IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {target}")


def validate_target(target: str) -> str:
    """Validate a target which can be IP, CIDR, or hostname."""
    target = target.strip()

    # Try IP address
    try:
        return validate_ip(target)
    except ValueError:
        pass

    # Try CIDR
    try:
        return validate_cidr(target)
    except ValueError:
        pass

    # Try hostname
    try:
        validate_hostname(target)
        return resolve_hostname(target)
    except ValueError:
        pass

    raise ValueError(
        f"Invalid target: '{target}'. Must be an IP address, CIDR range, or hostname."
    )


def validate_port_range(ports: str) -> list[int]:
    """Parse and validate port range string.

    Accepts formats like:
        - "80" (single port)
        - "1-1024" (range)
        - "22,80,443" (comma-separated)
        - "22,80,8000-9000" (mixed)
    """
    result: set[int] = set()

    for part in ports.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start.strip()), int(end.strip())
            except ValueError:
                raise ValueError(f"Invalid port range: {part}")

            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Port numbers must be 1-65535, got {part}")
            if start > end:
                raise ValueError(f"Invalid port range: start > end in {part}")

            result.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Invalid port number: {part}")

            if not (1 <= port <= 65535):
                raise ValueError(f"Port must be 1-65535, got {port}")
            result.add(port)

    return sorted(result)


COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 139, 143,
    161, 162, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995,
    1080, 1433, 1434, 1521, 2049, 3306, 3389, 5432, 5900, 5901, 6379,
    8080, 8443, 8888, 9090, 9200, 9300, 11211, 27017,
]


def get_default_ports() -> list[int]:
    """Return the default list of common ports to scan."""
    return COMMON_PORTS
