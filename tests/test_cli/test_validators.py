"""Tests for CLI validators."""

import pytest

from netscout.cli.validators import (
    validate_cidr,
    validate_ip,
    validate_port_range,
    validate_target,
)


class TestValidateIP:
    def test_valid_ipv4(self):
        assert validate_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv4_localhost(self):
        assert validate_ip("127.0.0.1") == "127.0.0.1"

    def test_valid_ipv6(self):
        assert validate_ip("::1") == "::1"

    def test_invalid_ip(self):
        with pytest.raises(ValueError, match="Invalid IP address"):
            validate_ip("not-an-ip")

    def test_invalid_ip_range(self):
        with pytest.raises(ValueError, match="Invalid IP address"):
            validate_ip("192.168.1.256")


class TestValidateCIDR:
    def test_valid_cidr(self):
        assert validate_cidr("192.168.1.0/24") == "192.168.1.0/24"

    def test_valid_cidr_16(self):
        assert validate_cidr("10.0.0.0/16") == "10.0.0.0/16"

    def test_valid_cidr_single(self):
        assert validate_cidr("192.168.1.1/32") == "192.168.1.1/32"

    def test_invalid_cidr(self):
        with pytest.raises(ValueError, match="Invalid CIDR"):
            validate_cidr("not-a-cidr")


class TestValidateTarget:
    def test_ip_target(self):
        assert validate_target("192.168.1.1") == "192.168.1.1"

    def test_cidr_target(self):
        assert validate_target("192.168.1.0/24") == "192.168.1.0/24"

    def test_whitespace_stripped(self):
        assert validate_target("  192.168.1.1  ") == "192.168.1.1"

    def test_invalid_target(self):
        with pytest.raises(ValueError, match="Invalid target"):
            validate_target("not-valid-at-all!!!")


class TestValidatePortRange:
    def test_single_port(self):
        assert validate_port_range("80") == [80]

    def test_port_range(self):
        assert validate_port_range("1-5") == [1, 2, 3, 4, 5]

    def test_comma_separated(self):
        assert validate_port_range("22,80,443") == [22, 80, 443]

    def test_mixed(self):
        result = validate_port_range("22,80,8000-8002")
        assert result == [22, 80, 8000, 8001, 8002]

    def test_invalid_port_number(self):
        with pytest.raises(ValueError, match="Port must be"):
            validate_port_range("0")

    def test_port_too_high(self):
        with pytest.raises(ValueError, match="Port must be"):
            validate_port_range("65536")

    def test_invalid_range(self):
        with pytest.raises(ValueError, match="Invalid port"):
            validate_port_range("abc")

    def test_range_start_greater_than_end(self):
        with pytest.raises(ValueError, match="start > end"):
            validate_port_range("100-50")
