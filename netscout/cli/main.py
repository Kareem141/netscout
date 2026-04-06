"""NetScout CLI - Main entry point."""

from __future__ import annotations

import time
from pathlib import Path

import typer

from netscout import __version__
from netscout.cli.privileges import check_privileges, is_root, warn_privilege_fallback
from netscout.cli.validators import (
    COMMON_PORTS,
    get_default_ports,
    validate_port_range,
    validate_target,
)
from netscout.output.models import HostResult, PortResult, ScanResult

app = typer.Typer(
    name="netscout",
    help="NetScout - Python CLI Network Scanner",
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"netscout v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """NetScout - A Python CLI network scanner using Scapy."""
    pass


@app.command("discover")
def discover(
    target: str = typer.Argument(..., help="Target IP, CIDR, or hostname."),
    method: str = typer.Option(
        "auto",
        "--method",
        "-m",
        help="Discovery method: auto, arp, icmp.",
    ),
    timeout: int = typer.Option(
        3,
        "--timeout",
        "-t",
        help="Timeout in seconds per host.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Show verbose output.",
    ),
) -> None:
    """Discover hosts on the network."""
    from netscout.scanner.arp_discovery import ARPDiscovery
    from netscout.scanner.icmp_sweep import ICMPSweep

    try:
        validated = validate_target(target)
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    if verbose:
        typer.echo(f"[*] Discovering hosts: {validated}")
        typer.echo(f"    Method: {method}")

    start = time.time()
    hosts: list[HostResult] = []

    if method in ("auto", "arp"):
        if is_root():
            scanner = ARPDiscovery(timeout=timeout)
            arp_results = scanner.scan(validated)
            hosts = [
                HostResult(ip=h["ip"], mac=h.get("mac", ""))
                for h in arp_results
            ]
            if verbose:
                typer.echo(f"[*] ARP discovery found {len(hosts)} hosts")
        elif method == "arp":
            typer.echo("[!] ARP discovery requires root. Falling back to ICMP.", err=True)
            method = "icmp"

    if method in ("auto", "icmp") and not hosts:
        if not is_root() and method == "auto":
            warn_privilege_fallback("ARP discovery")
        scanner = ICMPSweep(timeout=timeout)
        icmp_hosts = scanner.scan(validated)
        for icmp_host in icmp_hosts:
            hosts.append(HostResult(ip=icmp_host["ip"]))
        if verbose:
            typer.echo(f"[*] ICMP sweep found {len(icmp_hosts)} hosts")

    duration = time.time() - start

    if not hosts:
        typer.echo("[*] No hosts found.")
        raise typer.Exit(0)

    from netscout.analysis.mac_vendor import MACVendor
    from netscout.output.table import render_discovery_table

    mac_lookup = MACVendor()
    for host in hosts:
        if host.mac:
            vendor = mac_lookup.lookup(host.mac)
            if vendor:
                host.vendor = vendor

    render_discovery_table(hosts)

    result = ScanResult(
        target=target,
        hosts=hosts,
        duration_seconds=duration,
    )
    typer.echo(f"\n[*] Scan complete: {len(hosts)} hosts found in {duration:.2f}s")


@app.command("scan")
def scan(
    target: str = typer.Argument(..., help="Target IP or hostname."),
    ports: str = typer.Option(
        "common",
        "--ports",
        "-p",
        help="Port range (e.g., 1-1024, 22,80,443, or 'common').",
    ),
    syn: bool = typer.Option(
        False,
        "--syn",
        "-s",
        help="Use SYN scan (requires root).",
    ),
    banners: bool = typer.Option(
        False,
        "--banners",
        "-b",
        help="Grab service banners.",
    ),
    os_detect: bool = typer.Option(
        False,
        "--os-detect",
        "-O",
        help="Attempt OS detection.",
    ),
    timeout: int = typer.Option(
        2,
        "--timeout",
        "-t",
        help="Timeout in seconds per port.",
    ),
    output_format: str = typer.Option(
        "table",
        "--output",
        "-o",
        help="Output format: table, json, csv.",
    ),
    output_file: str = typer.Option(
        "",
        "--output-file",
        "-f",
        help="Output file path.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Show verbose output.",
    ),
) -> None:
    """Scan ports on a target host."""
    from netscout.scanner.banner_grab import BannerGrab
    from netscout.scanner.tcp_scan import TCPConnectScanner, TCPSynScanner

    try:
        validated = validate_target(target)
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    if ports == "common":
        port_list = get_default_ports()
    else:
        try:
            port_list = validate_port_range(ports)
        except ValueError as e:
            typer.echo(f"Error: {e}", err=True)
            raise typer.Exit(1)

    if verbose:
        typer.echo(f"[*] Scanning {validated}")
        typer.echo(f"    Ports: {len(port_list)} ports")
        typer.echo(f"    Method: {'SYN' if syn else 'Connect'}")

    start = time.time()

    use_syn = syn and is_root()
    if syn and not is_root():
        warn_privilege_fallback("SYN scan")

    if use_syn:
        scanner = TCPSynScanner(timeout=timeout)
    else:
        scanner = TCPConnectScanner(timeout=timeout)

    open_ports = scanner.scan(validated, port_list)

    if verbose:
        typer.echo(f"[*] Found {len(open_ports)} open ports")

    ports_result: list[PortResult] = []
    for port_info in open_ports:
        port_result = PortResult(
            port=port_info["port"],
            state="open",
            service=port_info.get("service", "unknown"),
        )
        ports_result.append(port_result)

    if banners and ports_result:
        if verbose:
            typer.echo("[*] Grabbing banners...")
        grabber = BannerGrab(timeout=timeout)
        for port_result in ports_result:
            if port_result.state == "open":
                banner = grabber.grab(validated, port_result.port)
                if banner:
                    port_result.banner = banner
                    if port_result.service == "unknown":
                        port_result.service = banner.split("\n")[0][:50]

    duration = time.time() - start

    host = HostResult(
        ip=validated,
        ports=ports_result,
    )

    if os_detect:
        from netscout.analysis.os_fingerprint import OSFingerprint

        os_fp = OSFingerprint()
        os_info = os_fp.detect(validated)
        host.os_guess = str(os_info.get("os", "unknown"))
        host.os_confidence = float(os_info.get("confidence", 0.0))

    result = ScanResult(
        target=target,
        hosts=[host],
        total_ports_scanned=len(port_list),
        total_open_ports=len(ports_result),
        duration_seconds=duration,
    )

    VALID_FORMATS = {"table", "json", "csv"}
    if output_format not in VALID_FORMATS:
        typer.echo(
            f"Error: Invalid output format '{output_format}'. Must be one of: {', '.join(sorted(VALID_FORMATS))}",
            err=True,
        )
        raise typer.Exit(1)

    if output_file:
        resolved_path = Path(output_file).resolve()
        cwd = Path.cwd().resolve()
        sensitive_prefixes = ("/etc/", "/usr/", "/var/", "/root/", "/boot/", "/sys/", "/proc/")
        if any(str(resolved_path).startswith(p) for p in sensitive_prefixes):
            typer.echo(f"Error: Cannot write to protected path: {output_file}", err=True)
            raise typer.Exit(1)

    if output_format == "json":
        from netscout.output.json_export import export_json

        json_str = export_json(result)
        if output_file:
            with open(output_file, "w") as f:
                f.write(json_str)
            typer.echo(f"[*] Results saved to {output_file}")
        else:
            typer.echo(json_str)
    elif output_format == "csv":
        from netscout.output.csv_export import export_csv

        csv_str = export_csv(result)
        if output_file:
            with open(output_file, "w") as f:
                f.write(csv_str)
            typer.echo(f"[*] Results saved to {output_file}")
        else:
            typer.echo(csv_str)
    else:
        from netscout.output.table import render_scan_table

        render_scan_table(result)

    typer.echo(f"\n[*] Scan complete: {len(ports_result)} open ports in {duration:.2f}s")


@app.command("os-detect")
def os_detect(
    target: str = typer.Argument(..., help="Target IP or hostname."),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Show verbose output.",
    ),
) -> None:
    """Detect operating system of a target host."""
    from netscout.analysis.os_fingerprint import OSFingerprint

    try:
        validated = validate_target(target)
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    if verbose:
        typer.echo(f"[*] Detecting OS for {validated}")

    os_fp = OSFingerprint()
    result = os_fp.detect(validated)

    typer.echo(f"\n  Target: {validated}")
    typer.echo(f"  OS: {result['os']}")
    typer.echo(f"  Confidence: {result['confidence']:.0%}")
    typer.echo(f"  TTL: {result.get('ttl', 'N/A')}")
    typer.echo("")


if __name__ == "__main__":
    app()
