"""JSON export for scan results."""

from __future__ import annotations

import json

from netscout.output.models import ScanResult


def export_json(result: ScanResult, pretty: bool = True) -> str:
    """Export scan results to JSON string.

    Args:
        result: ScanResult object.
        pretty: Whether to pretty-print the JSON.

    Returns:
        JSON string.
    """
    data = result.model_dump(mode="json")
    indent = 2 if pretty else None
    return json.dumps(data, indent=indent, default=str)
