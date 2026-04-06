"""Pydantic models for scan results."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class PortResult(BaseModel):
    """Result for a single port scan."""

    port: int
    protocol: str = "tcp"
    state: str  # open, closed, filtered
    service: str = "unknown"
    version: str = ""
    banner: str = ""


class HostResult(BaseModel):
    """Result for a single discovered host."""

    ip: str
    mac: str = ""
    vendor: str = "unknown"
    os_guess: str = "unknown"
    os_confidence: float = 0.0
    ports: list[PortResult] = Field(default_factory=list)
    hostname: str = ""


class ScanResult(BaseModel):
    """Top-level scan result container."""

    target: str
    scan_time: datetime = Field(default_factory=datetime.now)
    duration_seconds: float = 0.0
    hosts: list[HostResult] = Field(default_factory=list)
    total_ports_scanned: int = 0
    total_open_ports: int = 0

    @property
    def summary(self) -> dict:
        """Return a summary of the scan."""
        return {
            "target": self.target,
            "hosts_found": len(self.hosts),
            "total_ports_scanned": self.total_ports_scanned,
            "total_open_ports": self.total_open_ports,
            "duration_seconds": round(self.duration_seconds, 2),
        }
