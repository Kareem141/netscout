"""Rich colored table output rendering."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from netscout.output.models import HostResult, ScanResult

console = Console()


def render_discovery_table(hosts: list[HostResult]) -> None:
    """Render host discovery results as a colored table."""
    table = Table(title="Host Discovery Results", show_header=True)
    table.add_column("IP", style="cyan")
    table.add_column("MAC Address", style="green")
    table.add_column("Vendor", style="yellow")

    for host in hosts:
        table.add_row(
            host.ip,
            host.mac or "N/A",
            host.vendor,
        )

    console.print(table)


def render_scan_table(result: ScanResult) -> None:
    """Render port scan results as a colored table."""
    table = Table(title=f"Scan Results: {result.target}", show_header=True)
    table.add_column("Host", style="cyan")
    table.add_column("Port", style="green")
    table.add_column("State", style="yellow")
    table.add_column("Service", style="blue")
    table.add_column("Banner", style="dim")

    for host in result.hosts:
        if host.ports:
            for port in host.ports:
                state_style = {
                    "open": "bold green",
                    "closed": "red",
                    "filtered": "yellow",
                }.get(port.state, "white")

                table.add_row(
                    host.ip,
                    str(port.port),
                    f"[{state_style}]{port.state}[/{state_style}]",
                    port.service,
                    port.banner[:50] if port.banner else "",
                )
        else:
            table.add_row(host.ip, "-", "no open ports", "-", "")

    console.print(table)
    console.print(f"\n[bold]Summary:[/bold] {result.total_open_ports} open ports found on {len(result.hosts)} host(s)")
