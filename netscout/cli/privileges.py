"""Privilege detection and handling for root/sudo requirements."""

from __future__ import annotations

import os
import platform
import sys


def is_root() -> bool:
    """Check if the current process has root/administrator privileges."""
    if platform.system() == "Windows":
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def get_platform() -> str:
    """Return the current platform identifier."""
    system = platform.system()
    if system == "Linux":
        return "linux"
    elif system == "Darwin":
        return "macos"
    elif system == "Windows":
        return "windows"
    return system.lower()


def check_privileges(required: bool = True) -> bool:
    """Check privileges and return True if sufficient.

    Args:
        required: If True, exit with error message when not root.
                  If False, just return status.

    Returns:
        True if running with sufficient privileges.
    """
    if is_root():
        return True

    if not required:
        return False

    platform_name = get_platform()

    if platform_name == "linux":
        print(
            "[!] This operation requires root privileges.\n"
            "    Run with: sudo netscout <command>\n"
            "    Or use: sudo -E netscout <command> (preserves env)",
            file=sys.stderr,
        )
    elif platform_name == "macos":
        print(
            "[!] This operation requires root privileges.\n"
            "    Run with: sudo netscout <command>\n"
            "    Note: macOS SIP may restrict raw socket access.",
            file=sys.stderr,
        )
    elif platform_name == "windows":
        print(
            "[!] This operation requires Administrator privileges.\n"
            "    Run PowerShell/CMD as Administrator and execute:\n"
            "    netscout <command>",
            file=sys.stderr,
        )

    sys.exit(1)


def require_sudo() -> None:
    """Exit if not running as root. Convenience wrapper."""
    check_privileges(required=True)


def warn_privilege_fallback(method: str) -> None:
    """Warn about falling back to unprivileged method."""
    print(
        f"[!] {method} requires root privileges. "
        f"Falling back to unprivileged method.",
        file=sys.stderr,
    )
