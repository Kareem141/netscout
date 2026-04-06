"""CSV export for scan results."""

from __future__ import annotations

import csv
import io

from netscout.output.models import ScanResult


def export_csv(result: ScanResult) -> str:
    """Export scan results to CSV string.

    Flattens nested port data so each row is one port on one host.

    Args:
        result: ScanResult object.

    Returns:
        CSV string.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "host_ip",
        "host_mac",
        "host_vendor",
        "host_os",
        "host_os_confidence",
        "port",
        "protocol",
        "state",
        "service",
        "banner",
    ])

    for host in result.hosts:
        if host.ports:
            for port in host.ports:
                writer.writerow([
                    host.ip,
                    host.mac,
                    host.vendor,
                    host.os_guess,
                    host.os_confidence,
                    port.port,
                    port.protocol,
                    port.state,
                    port.service,
                    port.banner,
                ])
        else:
            writer.writerow([
                host.ip,
                host.mac,
                host.vendor,
                host.os_guess,
                host.os_confidence,
                "",
                "",
                "no ports scanned",
                "",
                "",
            ])

    return output.getvalue()
