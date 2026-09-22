"""Basic unit tests — no PCAP or network access required.

Run with:  python -m pytest tests/  (or  python -m unittest discover tests)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.correlator import risk_band
from analyzer.ioc_extractor import IOC
from utils.hashing import hashes_for, identify_signature
from utils.networking import (
    has_suspicious_extension,
    has_suspicious_user_agent,
    is_useful_ip,
)


class TestNetworking(unittest.TestCase):
    def test_private_ip_excluded(self):
        self.assertFalse(is_useful_ip("192.168.1.10"))
        self.assertFalse(is_useful_ip("10.0.0.5"))
        self.assertFalse(is_useful_ip("127.0.0.1"))

    def test_public_ip_included(self):
        self.assertTrue(is_useful_ip("8.8.8.8"))
        self.assertTrue(is_useful_ip("185.123.45.67"))

    def test_invalid_ip(self):
        self.assertFalse(is_useful_ip("not-an-ip"))

    def test_suspicious_user_agent(self):
        self.assertTrue(has_suspicious_user_agent("python-requests/2.31.0"))
        self.assertTrue(has_suspicious_user_agent("curl/8.4.0"))
        self.assertFalse(has_suspicious_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"))

    def test_suspicious_extension(self):
        self.assertTrue(has_suspicious_extension("/download/payload.exe"))
        self.assertTrue(has_suspicious_extension("/scripts/run.ps1?x=1"))
        self.assertFalse(has_suspicious_extension("/index.html"))


class TestHashing(unittest.TestCase):
    def test_hashes_for(self):
        digests = hashes_for(b"hello world")
        self.assertEqual(digests["md5"], "5eb63bbbe01eeed093cb22bb8f5acdc3")
        self.assertEqual(len(digests["sha256"]), 64)

    def test_identify_signature_pe(self):
        self.assertEqual(identify_signature(b"MZ\x90\x00" + b"\x00" * 60), "PE executable / DLL")

    def test_identify_signature_unknown(self):
        self.assertIsNone(identify_signature(b"not a known signature"))


class TestIOC(unittest.TestCase):
    def test_ioc_hashable_and_dict(self):
        ioc = IOC("185.123.45.67", "ipv4")
        self.assertEqual(ioc.to_dict(), {"indicator": "185.123.45.67", "type": "ipv4"})
        self.assertEqual(len({ioc, IOC("185.123.45.67", "ipv4")}), 1)


class TestRiskScoring(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(risk_band(5), "Informational")
        self.assertEqual(risk_band(25), "Low")
        self.assertEqual(risk_band(45), "Medium")
        self.assertEqual(risk_band(75), "High")
        self.assertEqual(risk_band(95), "Critical")


if __name__ == "__main__":
    unittest.main()
