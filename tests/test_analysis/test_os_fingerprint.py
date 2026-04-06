"""Tests for OS fingerprinting."""

from unittest.mock import MagicMock, patch

from netscout.analysis.os_fingerprint import OSFingerprint


class TestOSFingerprint:
    def test_detect_linux(self):
        with patch("netscout.analysis.os_fingerprint.sr1") as mock_sr1:
            mock_response = MagicMock()
            mock_ip = MagicMock()
            mock_ip.ttl = 64
            mock_response.haslayer.return_value = True
            mock_response.getlayer.return_value = mock_ip
            mock_sr1.return_value = mock_response

            fp = OSFingerprint()
            result = fp.detect("192.168.1.1")

            assert result["os"] == "Linux/Unix"
            assert result["confidence"] == 0.7
            assert result["ttl"] == 64

    def test_detect_windows(self):
        with patch("netscout.analysis.os_fingerprint.sr1") as mock_sr1:
            mock_response = MagicMock()
            mock_ip = MagicMock()
            mock_ip.ttl = 128
            mock_response.haslayer.return_value = True
            mock_response.getlayer.return_value = mock_ip
            mock_sr1.return_value = mock_response

            fp = OSFingerprint()
            result = fp.detect("192.168.1.1")

            assert result["os"] == "Windows"
            assert result["confidence"] == 0.7

    def test_detect_macos(self):
        with patch("netscout.analysis.os_fingerprint.sr1") as mock_sr1:
            mock_response = MagicMock()
            mock_ip = MagicMock()
            mock_ip.ttl = 255
            mock_response.haslayer.return_value = True
            mock_response.getlayer.return_value = mock_ip
            mock_sr1.return_value = mock_response

            fp = OSFingerprint()
            result = fp.detect("192.168.1.1")

            assert result["os"] == "macOS/FreeBSD"
            assert result["confidence"] == 0.6

    def test_detect_unknown(self):
        with patch("netscout.analysis.os_fingerprint.sr1") as mock_sr1:
            mock_sr1.return_value = None

            fp = OSFingerprint()
            result = fp.detect("192.168.1.1")

            assert result["os"] == "unknown"
            assert result["confidence"] == 0.0
            assert result["ttl"] == "N/A"

    def test_detect_exception_returns_unknown(self):
        with patch("netscout.analysis.os_fingerprint.sr1") as mock_sr1:
            mock_sr1.side_effect = Exception("Network error")

            fp = OSFingerprint()
            result = fp.detect("192.168.1.1")

            assert result["os"] == "unknown"
            assert result["confidence"] == 0.0
