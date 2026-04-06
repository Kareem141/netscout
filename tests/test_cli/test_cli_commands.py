"""Tests for CLI commands."""

from typer.testing import CliRunner

from netscout.cli.main import app

runner = CliRunner()


class TestCLICommands:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "netscout v" in result.stdout

    def test_help_flag(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "NetScout" in result.stdout

    def test_discover_help(self):
        result = runner.invoke(app, ["discover", "--help"])
        assert result.exit_code == 0
        assert "Discover hosts" in result.stdout

    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan ports" in result.stdout

    def test_os_detect_help(self):
        result = runner.invoke(app, ["os-detect", "--help"])
        assert result.exit_code == 0
        assert "Detect operating system" in result.stdout

    def test_discover_invalid_target(self):
        result = runner.invoke(app, ["discover", "not-a-valid-target"])
        assert result.exit_code == 1
        output = result.stdout + (result.stderr or "")
        assert "Invalid" in output or "Error" in output or "invalid" in output.lower()

    def test_scan_invalid_target(self):
        result = runner.invoke(app, ["scan", "not-a-valid-target"])
        assert result.exit_code == 1

    def test_scan_invalid_ports(self):
        result = runner.invoke(app, ["scan", "192.168.1.1", "--ports", "abc"])
        assert result.exit_code == 1
